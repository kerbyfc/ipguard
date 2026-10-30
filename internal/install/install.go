package install

import (
	"bufio"
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/kerbyfc/ipguard/internal/config"
	"github.com/kerbyfc/ipguard/internal/guard"
	"github.com/kerbyfc/ipguard/internal/proxy"
)

const (
	// probeMargin — запас пробы сверх одной попытки проверки: `/status` ждёт вердикт, а
	// вердикт начинается с запроса к источнику. Проба короче попытки отчиталась бы отказом
	// о живой службе; полный бюджет установка не ждёт и говорит об этом прямо.
	probeMargin = 15 * time.Second
	// startTimeout — сколько ждать, пока автозапуск поднимет слушателя.
	startTimeout = 15 * time.Second
	// startPoll — пауза между попытками достучаться до слушателя.
	startPoll = 300 * time.Millisecond
	// secretBytes — длина секрета: 16 байт случайности, 32 знака в шестнадцатеричной записи.
	secretBytes = 16

	configTemplate = `# Settings of the Claude access guard (ipguard). The other fields keep their built-in
# values; the README next to this file lists them and explains what they mean.
expected_ip: %s
secret: %s
`
)

// Probe — проба живого сервиса: ответ `/status` уже поднятого прокси.
type Probe func(ctx context.Context, settings config.Settings) (proxy.StatusView, error)

// Options — из чего установка собрана. Всё, что ходит в ОС и в сеть, вынесено в поля:
// тесты подменяют их и не трогают ни launchd, ни хост проверки.
type Options struct {
	// ExpectedIP — ожидаемый внешний IP для нового файла настроек; пусто — спросить у хоста
	// проверки.
	ExpectedIP string
	// AssumeYes — не спрашивать подтверждения найденного адреса.
	AssumeYes bool
	// Paths — адреса установки.
	Paths Paths
	// Service — автозапуск ОС.
	Service Service
	// Self — бинарник, который ставится (обычно собственный путь процесса).
	Self string
	// Out — куда идёт отчёт по шагам.
	Out io.Writer
	// In — откуда читается подтверждение найденного адреса.
	In io.Reader
	// Interactive — можно ли спрашивать владельца.
	Interactive bool
	// Detect — внешний IP для подсказки при создании настроек.
	Detect func(ctx context.Context) (string, error)
	// Await ждёт, пока автозапуск поднимет слушателя.
	Await func(ctx context.Context, address string) error
	// Probe — проба живого сервиса.
	Probe Probe
	// Secret — генератор секрета прокси.
	Secret func() (string, error)
}

// DefaultOptions — установка на эту машину.
func DefaultOptions(goos string) (Options, error) {
	paths, err := DefaultPaths(goos)
	if err != nil {
		return Options{}, err
	}

	service, err := PickService(goos, paths, ExecRunner)
	if err != nil {
		return Options{}, err
	}

	self, err := os.Executable()
	if err != nil {
		return Options{}, fmt.Errorf("%w: own path is unknown: %w", ErrInstall, err)
	}

	return Options{
		ExpectedIP:  "",
		AssumeYes:   false,
		Paths:       paths,
		Service:     service,
		Self:        self,
		Out:         os.Stdout,
		In:          os.Stdin,
		Interactive: isTerminal(os.Stdin),
		Detect:      DetectIP,
		Await:       WaitListener,
		Probe:       LocalProbe,
		Secret:      NewSecret,
	}, nil
}

// Install ставит сторожа и кончает пробой живого сервиса. Каждый шаг идемпотентен: уже
// сделанное подтверждается строкой отчёта и не переделывается.
func Install(ctx context.Context, options Options) error {
	report := reporter{out: options.Out}
	report.line("ipguard install (+ done, = already done)")

	directory, err := ensureDir(options.Paths.Dir)
	report.step("directory", directory)

	if err != nil {
		return err
	}

	binary, err := ensureBinary(options.Self, options.Paths.Binary)
	report.step("binary", binary)

	if err != nil {
		return err
	}

	// Шаг идёт до чтения настроек: оставшийся ключ guarded_hosts — отказ загрузки, и
	// переписать его надо раньше, чем файл прочитают.
	whitelist, err := ensureUnguardedHosts(options.Paths.Config)
	report.step("hosts", whitelist)

	if err != nil {
		return err
	}

	settings, written, err := ensureConfig(ctx, options)
	report.step("settings", written)

	if err != nil {
		return err
	}

	access, err := ensureAccess(options.Paths)
	report.step("access", access)

	if err != nil {
		return err
	}

	autostart, err := options.Service.Ensure(options.Paths.Binary)
	report.step("autostart", autostart)

	if err != nil {
		return err //nolint:wrapcheck // Service оборачивает ErrInstall сам
	}

	err = startService(options, binary, report)
	if err != nil {
		return err
	}

	err = probeService(ctx, options, settings, report)
	if err != nil {
		return err
	}

	report.ending(options.Paths, settings, options.Service.Describe())

	return nil
}

// Uninstall снимает автозапуск и останавливает службу. Настройки, журнал и бинарник
// остаются: в настройках секрет, а в журнале история отказов.
func Uninstall(options Options) error {
	report := reporter{out: options.Out}
	report.line("ipguard uninstall (+ done, = already done)")

	autostart, err := options.Service.Remove()
	report.step("autostart", autostart)

	if err != nil {
		return err //nolint:wrapcheck // Service оборачивает ErrInstall сам
	}

	report.step("mechanism", Change{Done: false, Note: options.Service.Describe()})
	report.step("settings", Change{Done: false, Note: "kept, " + options.Paths.Config})
	report.step("binary", Change{Done: false, Note: "kept, " + options.Paths.Binary})
	report.line("")
	report.line("the proxy in claude is dropped separately: ipguard disable")

	return nil
}

// NewSecret — секрет прокси: 32 знака случайности.
func NewSecret() (string, error) {
	raw := make([]byte, secretBytes)

	_, err := rand.Read(raw)
	if err != nil {
		return "", fmt.Errorf("%w: secret generation failed: %w", ErrInstall, err)
	}

	return hex.EncodeToString(raw), nil
}

// DetectIP спрашивает внешний IP у хоста проверки из встроенных значений: его ответ —
// подсказка при создании настроек, а не вердикт.
func DetectIP(ctx context.Context) (string, error) {
	timed, cancel := context.WithTimeout(ctx, config.DefaultAttemptTimeout)
	defer cancel()

	address, err := guard.FetchIP(timed, config.DefaultCheckURL, "")
	if err != nil {
		return "", fmt.Errorf("%w: %w", ErrInstall, err)
	}

	return address, nil
}

// probeTimeout — сколько установка ждёт ответа `/status`: одна попытка проверки с запасом.
// Так проба не короче самой проверки при любой настройке `attempt_timeout`.
func probeTimeout(settings config.Settings) time.Duration {
	return settings.AttemptTimeout + probeMargin
}

// LocalProbe спрашивает `/status` у слушателя из настроек. Окружение процесса не читается:
// проба идёт к своему же прокси напрямую, а не через чужой верхний прокси.
func LocalProbe(ctx context.Context, settings config.Settings) (proxy.StatusView, error) {
	view := proxy.StatusView{} //nolint:exhaustruct // заполняется разбором ответа

	transport, ok := http.DefaultTransport.(*http.Transport)
	if !ok {
		return view, fmt.Errorf("%w: default transport has unexpected type", ErrInstall)
	}

	cloned := transport.Clone()
	cloned.Proxy = nil

	request, err := http.NewRequestWithContext(
		ctx, http.MethodGet, "http://"+settings.ListenAddr()+"/status", http.NoBody,
	)
	if err != nil {
		return view, fmt.Errorf("%w: %w", ErrInstall, err)
	}

	request.SetBasicAuth("claude", settings.Secret)

	client := &http.Client{Transport: cloned, CheckRedirect: nil, Jar: nil, Timeout: probeTimeout(settings)}

	response, err := client.Do(request)
	if err != nil {
		return view, fmt.Errorf("%w: %w", ErrInstall, err)
	}

	defer func() { _ = response.Body.Close() }()

	if response.StatusCode != http.StatusOK {
		return view, fmt.Errorf("%w: /status answered %s", ErrInstall, response.Status)
	}

	err = json.NewDecoder(response.Body).Decode(&view)
	if err != nil {
		return view, fmt.Errorf("%w: /status answer is not readable: %w", ErrInstall, err)
	}

	return view, nil
}

// startService поднимает службу. Обещание установки — после неё сторож слушает порт, поэтому
// шаг идёт всегда: запись автозапуска сама процесс не поднимает (задача планировщика Windows
// ждёт входа в систему, а launchd-служба могла выйти), и тот же шаг нужен уже работающей
// службе со сменившимся бинарником — его она подхватывает только перезапуском.
func startService(options Options, binary Change, report reporter) error {
	if binary.Done {
		err := options.Service.Restart()
		if err != nil {
			return err //nolint:wrapcheck // Service оборачивает ErrInstall сам
		}

		report.step("service", Change{Done: true, Note: "restarted onto the new binary"})

		return nil
	}

	err := options.Service.Start()
	if err != nil {
		return err //nolint:wrapcheck // Service оборачивает ErrInstall сам
	}

	report.step("service", Change{Done: true, Note: "started"})

	return nil
}

// probeService ждёт слушателя и спрашивает у него вердикт: отчёт установки кончается тем,
// что в этот момент говорит сам сервис.
func probeService(ctx context.Context, options Options, settings config.Settings, report reporter) error {
	err := options.Await(ctx, settings.ListenAddr())
	if err != nil {
		return fmt.Errorf("%w (journal %s)", err, settings.LogPath)
	}

	view, err := options.Probe(ctx, settings)
	if err != nil {
		report.step("probe", Change{
			Done: false,
			Note: "the service listens on " + settings.ListenAddr() + " but gave no verdict: " + err.Error(),
		})

		// Сервис не ответил — установка не проверена: 407 от своего же прокси, таймаут и
		// битый ответ — поломки, а не вердикт, и код возврата это называет.
		return fmt.Errorf(
			"%w: the service listens on %s but gave no verdict, so the install is not verified: %w",
			ErrInstall, settings.ListenAddr(), err,
		)
	}

	note := fmt.Sprintf(
		"verdict %s, external IP %s, expected %s",
		view.Verdict, view.IP, view.ExpectedIP,
	)
	if !view.Allowed {
		note = "TRAFFIC IS BLOCKED — " + view.Message
		if view.LastError != "" {
			note += " (last error: " + view.LastError + ")"
		}
	}

	report.step("probe", Change{Done: true, Note: note})

	return nil
}

// WaitListener ждёт, пока автозапуск поднимет слушателя.
func WaitListener(ctx context.Context, address string) error {
	deadline := time.Now().Add(startTimeout)
	dialer := net.Dialer{Timeout: startPoll} //nolint:exhaustruct // срок попытки — единственная нужная настройка

	for {
		connection, err := dialer.DialContext(ctx, "tcp", address)
		if err == nil {
			_ = connection.Close()

			return nil
		}

		if time.Now().After(deadline) {
			return fmt.Errorf("%w: nobody listens on %s after %s", ErrInstall, address, startTimeout)
		}

		select {
		case <-ctx.Done():
			return fmt.Errorf("%w: %w", ErrInstall, ctx.Err())
		case <-time.After(startPoll):
		}
	}
}

// ensureBinary кладёт бинарник в каталог запуска. Тот же файл на месте — шаг пропускается.
func ensureBinary(self, target string) (Change, error) {
	// Копии, уведённые в сторону прошлыми установками, убираются каждым запуском: держащий
	// их процесс к этому времени вышел, и бинарники в каталоге запуска не копятся.
	sweepAside(target)

	if self == target {
		return Change{Done: false, Note: "already in place, " + target}, nil
	}

	content, err := os.ReadFile(self)
	if err != nil {
		return Change{Done: false, Note: ""}, fmt.Errorf("%w: %s: %w", ErrInstall, self, err)
	}

	same, err := fileHasContent(target, content)
	if err != nil {
		return Change{Done: false, Note: ""}, err
	}

	if same {
		return Change{Done: false, Note: "already the same, " + target}, nil
	}

	err = writeFile(target, content, binaryMode)
	if err != nil {
		return Change{Done: false, Note: ""}, err
	}

	return Change{Done: true, Note: "installed, " + target}, nil
}

// ensureConfig держит файл настроек. Файл уже есть — он не переписывается: в нём секрет и
// решения владельца, а установка не вправе их менять.
func ensureConfig(ctx context.Context, options Options) (config.Settings, Change, error) {
	empty := config.Settings{} //nolint:exhaustruct // возврат на отказе до чтения настроек

	_, err := os.Stat(options.Paths.Config)

	switch {
	case err == nil:
		return existingConfig(options)
	case os.IsNotExist(err):
	default:
		return empty, Change{Done: false, Note: ""},
			fmt.Errorf("%w: %s: %w", ErrInstall, options.Paths.Config, err)
	}

	return newConfig(ctx, options)
}

// existingConfig читает уже лежащий файл настроек и отказывает, если просьба владельца с ним
// расходится.
func existingConfig(options Options) (config.Settings, Change, error) {
	settings, err := config.Load(options.Paths.Config)
	if err != nil {
		return settings, Change{Done: false, Note: ""}, err //nolint:wrapcheck // config оборачивает сам
	}

	err = settings.RequireSecret()
	if err != nil {
		return settings, Change{Done: false, Note: ""}, err //nolint:wrapcheck // config оборачивает сам
	}

	if options.ExpectedIP != "" && options.ExpectedIP != settings.ExpectedIP {
		return settings, Change{Done: false, Note: ""}, fmt.Errorf(
			"%w: settings already expect %s, --expected-ip says %s: edit %s yourself",
			ErrInstall, settings.ExpectedIP, options.ExpectedIP, options.Paths.Config,
		)
	}

	return settings, Change{
		Done: false,
		Note: "already there, " + options.Paths.Config + " (expected IP " + settings.ExpectedIP + ")",
	}, nil
}

// newConfig создаёт файл настроек с ожидаемым адресом и новым секретом.
func newConfig(ctx context.Context, options Options) (config.Settings, Change, error) {
	empty := config.Settings{} //nolint:exhaustruct // возврат на отказе до чтения настроек

	expected, err := resolveExpectedIP(ctx, options)
	if err != nil {
		return empty, Change{Done: false, Note: ""}, err
	}

	secret, err := options.Secret()
	if err != nil {
		return empty, Change{Done: false, Note: ""}, err
	}

	content := appendBlock(
		fmt.Sprintf(configTemplate, expected, secret),
		unguardedBlock(config.DefaultUnguardedHosts()),
	)

	err = writeFile(options.Paths.Config, []byte(content), secretMode)
	if err != nil {
		return empty, Change{Done: false, Note: ""}, err
	}

	settings, err := config.Load(options.Paths.Config)
	if err != nil {
		return settings, Change{Done: false, Note: ""}, err //nolint:wrapcheck // config оборачивает сам
	}

	return settings, Change{
		Done: true,
		Note: "created, " + options.Paths.Config + " (expected IP " + expected + ", new secret)",
	}, nil
}

// resolveExpectedIP берёт ожидаемый адрес из просьбы владельца или спрашивает его у хоста
// проверки. Молча подставить встроенный адрес нельзя: сторож пускал бы трафик не по той
// настройке.
func resolveExpectedIP(ctx context.Context, options Options) (string, error) {
	if options.ExpectedIP != "" {
		if net.ParseIP(options.ExpectedIP) == nil {
			return "", fmt.Errorf("%w: --expected-ip %q is not an IP address", ErrInstall, options.ExpectedIP)
		}

		return options.ExpectedIP, nil
	}

	detected, err := options.Detect(ctx)
	if err != nil {
		return "", err
	}

	if options.AssumeYes {
		return detected, nil
	}

	if !options.Interactive {
		return "", fmt.Errorf(
			"%w: external IP now is %s; pass --expected-ip <ip> or --yes to accept it",
			ErrInstall, detected,
		)
	}

	return confirmIP(options, detected)
}

// confirmIP спрашивает владельца, записывать ли найденный адрес ожидаемым.
func confirmIP(options Options, detected string) (string, error) {
	_, _ = fmt.Fprintf(options.Out, "  ? external IP is %s right now. Record it as the expected one? [y/N] ", detected)

	answer, err := bufio.NewReader(options.In).ReadString('\n')
	if err != nil && !strings.HasSuffix(err.Error(), "EOF") {
		return "", fmt.Errorf("%w: %w", ErrInstall, err)
	}

	switch strings.ToLower(strings.TrimSpace(answer)) {
	case "y", "yes", "д", "да":
		return detected, nil
	default:
		return "", fmt.Errorf("%w: expected IP not confirmed: pass --expected-ip <ip>", ErrInstall)
	}
}

// isTerminal — можно ли спрашивать владельца в этом запуске.
func isTerminal(file *os.File) bool {
	info, err := file.Stat()
	if err != nil {
		return false
	}

	return info.Mode()&os.ModeCharDevice != 0
}
