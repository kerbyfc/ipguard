package install_test

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"unicode/utf16"

	"github.com/kerbyfc/ipguard/internal/config"
	"github.com/kerbyfc/ipguard/internal/install"
	"github.com/kerbyfc/ipguard/internal/proxy"
)

// testSecret — секрет, который подставляется вместо случайного: по нему видно, что файл
// настроек не переписан вторым запуском.
const testSecret = "0123456789abcdef0123456789abcdef"

// errFake — отказ подложной команды ОС или подложного хоста проверки.
var errFake = errors.New("подложный отказ")

// errBootstrap — отказ launchd на `bootstrap` сразу после `bootout`: ровно то, что видел
// владелец, когда ярлык ещё держал домен.
var errBootstrap = errors.New(
	"launchctl bootstrap gui/501/" + install.Label +
		": exit status 5: Bootstrap failed: 5: Input/output error",
)

var (
	// errPermanentBootstrap — постоянный отказ launchd, который не лечится ожиданием.
	errPermanentBootstrap = errors.New(
		"launchctl bootstrap: Bootstrap failed: 2: No such file or directory",
	)
	// errBrokenPlist — ответ `plutil -lint` на негодную запись.
	errBrokenPlist = errors.New("unexpected character at line 1")
	// errNoSuchProcess — `bootout` службы, которой уже нет.
	errNoSuchProcess = errors.New("launchctl bootout: No such process")
	// errInProgress — `bootout` в момент, когда домен ещё занят.
	errInProgress = errors.New("launchctl bootout: Operation now in progress")
)

// fakeService — автозапуск, который ничего не делает с машиной: тесты не трогают ни launchd,
// ни планировщик задач Windows. Процесс он тоже только изображает: running поднимается
// запуском и перезапуском, и по нему виден главный инвариант установки — после неё служба
// идёт.
type fakeService struct {
	binary   string
	ensured  int
	starts   int
	restarts int
	removed  int
	set      bool
	running  bool
}

// Describe — имя механизма автозапуска для отчёта.
func (service *fakeService) Describe() string {
	return "подложный автозапуск"
}

// Ensure запоминает бинарник; второй вызов подтверждает уже настроенный автозапуск.
func (service *fakeService) Ensure(binary string) (install.Change, error) {
	service.ensured++
	service.binary = binary

	if service.set {
		return install.Change{Done: false, Note: "уже настроен"}, nil
	}

	service.set = true

	return install.Change{Done: true, Note: "настроен"}, nil
}

// Start поднимает подложную службу: запись автозапуска процесс не поднимает.
func (service *fakeService) Start() error {
	service.starts++
	service.running = true

	return nil
}

// Restart считает перезапуски.
func (service *fakeService) Restart() error {
	service.restarts++
	service.running = true

	return nil
}

// Installed — заведён ли подложный автозапуск: его заводит Ensure.
func (service *fakeService) Installed() (bool, error) {
	return service.set, nil
}

// Remove снимает подложный автозапуск.
func (service *fakeService) Remove() (install.Change, error) {
	service.removed++
	service.set = false
	service.running = false

	return install.Change{Done: true, Note: "снят"}, nil
}

// commandLog — подложный запуск команд ОС: пишет вызовы и отвечает заранее заданным.
type commandLog struct {
	calls      []string
	createdXML []byte
	queryXML   string
	registered bool
	queryFails bool
	// bootoutLinger — сколько проверок после `bootout` ещё видят ярлык в домене.
	bootoutLinger int
	// lingering — остаток bootoutLinger на нынешнем снятии.
	lingering int
	// bootstrapFails — сколько первых `bootstrap` откажут errBootstrap.
	bootstrapFails int
	// bootstrapError — чем отказывает `bootstrap`, если задан; иначе errBootstrap.
	bootstrapError error
	// bootstraps — сколько раз звали `bootstrap`.
	bootstraps int
	// bootoutErrors — ответы `bootout` по одному на вызов; пусто — успех.
	bootoutErrors []error
	// plistErr — ответ `plutil -lint` на запись автозапуска.
	plistErr error
	// aliveProcesses — сколько первых ответов `tasklist` назовут процесс службы живым:
	// `/End` асинхронный, и процесс уходит не сразу.
	aliveProcesses int
}

// Run — Runner для Service: отвечает за launchctl и schtasks, не запуская их.
func (log *commandLog) Run(name string, args ...string) (string, error) {
	log.calls = append(log.calls, strings.Join(append([]string{name}, args...), " "))

	if len(args) == 0 {
		return "", nil
	}

	switch name {
	case "launchctl":
		return log.launchctl(args)
	case "plutil":
		return "", log.plistErr
	case "schtasks":
		return log.schtasks(args)
	case "tasklist":
		return log.tasklist(args)
	default:
		return "", nil
	}
}

// launchctl отвечает за команды домена: печать, снятие и постановку службы.
func (log *commandLog) launchctl(args []string) (string, error) {
	switch args[0] {
	case "print":
		return log.launchctlPrint()
	case "bootout":
		return log.launchctlBootout()
	case "bootstrap":
		return log.launchctlBootstrap()
	}

	return "", nil
}

// launchctlPrint отвечает, зарегистрирована ли служба. `bootout` асинхронный: сначала ярлык
// ещё виден в домене, потом исчезает.
func (log *commandLog) launchctlPrint() (string, error) {
	if log.lingering > 0 {
		log.lingering--

		return "", nil
	}

	if !log.registered {
		return "", errFake
	}

	return "", nil
}

// launchctlBootout снимает службу; «No such process» значит, что её уже нет.
func (log *commandLog) launchctlBootout() (string, error) {
	if len(log.bootoutErrors) > 0 {
		err := log.bootoutErrors[0]
		log.bootoutErrors = log.bootoutErrors[1:]

		if err != nil {
			if strings.Contains(strings.ToLower(err.Error()), "no such process") {
				log.registered = false
			}

			return "", err
		}
	}

	log.registered = false
	log.lingering = log.bootoutLinger

	return "", nil
}

// launchctlBootstrap возвращает службу в домен — так же, как настоящий launchctl.
func (log *commandLog) launchctlBootstrap() (string, error) {
	log.bootstraps++

	if log.bootstrapFails > 0 {
		log.bootstrapFails--

		if log.bootstrapError != nil {
			return "", log.bootstrapError
		}

		return "", errBootstrap
	}

	log.registered = true

	return "", nil
}

// schtasks отвечает за запрос и создание задачи планировщика.
func (log *commandLog) schtasks(args []string) (string, error) {
	switch args[0] {
	case "/Query":
		if log.queryFails {
			return "", errFake
		}

		return log.queryXML, nil
	case "/Create":
		log.createdXML = log.readUnit(args)

		return "", nil
	default:
		return "", nil
	}
}

// tasklist отвечает, жив ли процесс службы: сперва — тем, что жив, потом — тем, что его нет,
// как настоящий список процессов после `/End`.
func (log *commandLog) tasklist(args []string) (string, error) {
	image := ""

	for _, arg := range args {
		if strings.HasPrefix(arg, "IMAGENAME eq ") {
			image = strings.TrimPrefix(arg, "IMAGENAME eq ")
		}
	}

	if log.aliveProcesses > 0 {
		log.aliveProcesses--

		return `"` + image + `","4242","Console","1","12 345 КБ"`, nil
	}

	return "INFO: No tasks are running which match the specified criteria.", nil
}

// called — был ли вызов, в строке которого есть part.
func (log *commandLog) called(part string) bool {
	for _, call := range log.calls {
		if strings.Contains(call, part) {
			return true
		}
	}

	return false
}

// readUnit читает файл записи, который `schtasks /Create` получает аргументом: после вызова
// установка его удаляет, поэтому содержимое снимается здесь.
func (log *commandLog) readUnit(args []string) []byte {
	for index, arg := range args {
		if arg == "/XML" && index+1 < len(args) {
			content, err := os.ReadFile(args[index+1])
			if err != nil {
				return nil
			}

			return content
		}
	}

	return nil
}

// stand — установка на подложных путях: своя домашняя папка, свой бинарник, поддельный
// автозапуск и подменённые проба, ожидание слушателя и хост проверки.
type stand struct {
	paths   install.Paths
	service *fakeService
	out     *bytes.Buffer
	options install.Options
	self    string
}

// newStand собирает установку, которая не ходит ни в ОС, ни в сеть.
func newStand(t *testing.T) *stand {
	t.Helper()

	home := t.TempDir()

	paths, err := install.NewPaths(install.GOOSDarwin, home)
	if err != nil {
		t.Fatalf("paths for %s: %v", home, err)
	}

	self := filepath.Join(home, "source", install.BinaryName)
	writeTestFile(t, self, "binary-one")

	service := &fakeService{
		binary:   "",
		ensured:  0,
		starts:   0,
		restarts: 0,
		removed:  0,
		set:      false,
		running:  false,
	}
	out := &bytes.Buffer{}

	return &stand{
		paths:   paths,
		service: service,
		out:     out,
		self:    self,
		options: install.Options{
			ExpectedIP:  "203.0.113.9",
			AssumeYes:   false,
			Paths:       paths,
			Service:     service,
			Self:        self,
			Out:         out,
			In:          strings.NewReader(""),
			Interactive: false,
			Detect:      failingDetect,
			Await:       serviceListener(service),
			Probe:       allowedProbe,
			Secret:      func() (string, error) { return testSecret, nil },
		},
	}
}

// writeTestFile кладёт файл вместе с его каталогом.
func writeTestFile(t *testing.T, path, content string) {
	t.Helper()

	err := os.MkdirAll(filepath.Dir(path), 0o700)
	if err != nil {
		t.Fatalf("mkdir %s: %v", filepath.Dir(path), err)
	}

	err = os.WriteFile(path, []byte(content), 0o600)
	if err != nil {
		t.Fatalf("write %s: %v", path, err)
	}
}

// openTestPath открывает путь другим пользователям машины — так выглядит каталог прежней
// установки. На POSIX это права, на Windows — включённое наследование от профиля.
func openTestPath(t *testing.T, path string, mode os.FileMode) {
	t.Helper()

	if runtime.GOOS == install.GOOSWindows {
		output, err := exec.Command("icacls", path, "/inheritance:e").CombinedOutput()
		if err != nil {
			t.Fatalf("icacls %s: %v: %s", path, err, output)
		}

		return
	}

	err := os.Chmod(path, mode)
	if err != nil {
		t.Fatalf("chmod %s: %v", path, err)
	}
}

// requireOwnerOnly — путь закрыт от других пользователей машины. На POSIX это права 0600 и
// 0700, на Windows прав нет: там закрывает ACL, и проверяется он — ровно одна запись
// доступа, и она своя, не унаследованная от профиля (`(I)` у `icacls`).
func requireOwnerOnly(t *testing.T, path string, mode os.FileMode) {
	t.Helper()

	if runtime.GOOS == install.GOOSWindows {
		output, err := exec.Command("icacls", path).CombinedOutput()
		if err != nil {
			t.Fatalf("icacls %s: %v: %s", path, err, output)
		}

		entries := make([]string, 0, 4)

		for _, line := range strings.Split(string(output), "\n") {
			line = strings.TrimSpace(line)
			if line == "" {
				break
			}

			if strings.Contains(line, ":(") {
				entries = append(entries, line)
			}
		}

		if len(entries) != 1 || strings.Contains(entries[0], "(I)") {
			t.Fatalf("ACL of %s is %v, want one own entry: the file holds the secret", path, entries)
		}

		return
	}

	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("stat %s: %v", path, err)
	}

	if info.Mode().Perm() != mode {
		t.Fatalf("mode of %s is %v, want %v: the file holds the secret", path, info.Mode().Perm(), mode)
	}
}

// readTestFile читает файл или валит тест.
func readTestFile(t *testing.T, path string) string {
	t.Helper()

	content, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}

	return string(content)
}

// stepMark — знак шага name в отчёте установки: `+` сделано, `=` уже так.
func stepMark(t *testing.T, report, name string) string {
	t.Helper()

	for _, line := range strings.Split(report, "\n") {
		fields := strings.Fields(line)
		if len(fields) >= 2 && fields[1] == name && (fields[0] == "+" || fields[0] == "=") {
			return fields[0]
		}
	}

	t.Fatalf("report has no step %q:\n%s", name, report)

	return ""
}

// failingDetect — хост проверки, который в тестах не опрашивается.
func failingDetect(_ context.Context) (string, error) {
	return "", errFake
}

// serviceListener — слушатель поднятой службы: пока процесс не запущен, порт не отвечает.
// Иначе фальшивка скрывала бы дыру «запись автозапуска есть, процесса нет».
func serviceListener(service *fakeService) func(context.Context, string) error {
	return func(_ context.Context, address string) error {
		if !service.running {
			return fmt.Errorf("%w: nobody listens on %s", install.ErrInstall, address)
		}

		return nil
	}
}

// allowedProbe — ответ сервиса «трафик пускается».
func allowedProbe(_ context.Context, settings config.Settings) (proxy.StatusView, error) {
	return proxy.StatusView{
		UnguardedHosts:   nil,
		SeenHosts:        nil,
		SeenLimitReached: false,
		Verdict:          "allowed",
		Allowed:          true,
		IP:               settings.ExpectedIP,
		LastError:        "",
		CheckedAt:        "2026-10-19T12:00:00Z",
		Message:          "external IP matches the expected one",
		ExpectedIP:       settings.ExpectedIP,
		CheckURL:         settings.CheckURL,
		Budget:           settings.Budget.String(),
	}, nil
}

// blockedProbe — ответ сервиса «трафик закрыт».
func blockedProbe(_ context.Context, settings config.Settings) (proxy.StatusView, error) {
	return proxy.StatusView{
		UnguardedHosts:   nil,
		SeenHosts:        nil,
		SeenLimitReached: false,
		Verdict:          "blocked",
		Allowed:          false,
		IP:               "198.51.100.4",
		LastError:        "dial tcp: timeout",
		CheckedAt:        "2026-10-19T12:00:00Z",
		Message:          "external IP is not the expected one: 198.51.100.4 instead of " + settings.ExpectedIP,
		ExpectedIP:       settings.ExpectedIP,
		CheckURL:         settings.CheckURL,
		Budget:           settings.Budget.String(),
	}, nil
}

// detected — хост проверки, отвечающий адресом address.
func detected(address string) func(context.Context) (string, error) {
	return func(_ context.Context) (string, error) {
		return address, nil
	}
}

// encodeTestUTF16 — UTF-16 с BOM: только такой XML принимает и отдаёт `schtasks`.
func encodeTestUTF16(text string) string {
	units := utf16.Encode([]rune(text))
	data := make([]byte, 0, 2*len(units)+2)
	data = append(data, 0xFF, 0xFE)

	for _, unit := range units {
		data = append(data, byte(unit), byte(unit>>8))
	}

	return string(data)
}

// decodeTestUTF16 читает XML задачи, записанный установкой.
func decodeTestUTF16(data []byte) string {
	if len(data) < 2 || data[0] != 0xFF || data[1] != 0xFE {
		return string(data)
	}

	data = data[2:]
	units := make([]uint16, 0, len(data)/2)

	for index := 0; index+1 < len(data); index += 2 {
		units = append(units, uint16(data[index])|uint16(data[index+1])<<8)
	}

	return string(utf16.Decode(units))
}
