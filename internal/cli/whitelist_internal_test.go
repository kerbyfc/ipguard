package cli

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/spf13/viper"

	"github.com/kerbyfc/ipguard/internal/config"
	"github.com/kerbyfc/ipguard/internal/install"
)

// testService — автозапуск, который ничего не делает с машиной: тест не трогает ни launchd,
// ни планировщик задач Windows.
type testService struct {
	installed bool
	restarts  int
}

// Describe — имя механизма автозапуска для отчёта.
func (service *testService) Describe() string {
	return "подложный автозапуск"
}

// Ensure автозапуск не настраивает: команде белого списка это не нужно.
func (service *testService) Ensure(string) (install.Change, error) {
	return install.Change{Done: false, Note: ""}, nil
}

// Start службу не поднимает.
func (service *testService) Start() error {
	return nil
}

// Restart считает перезапуски: ими правка вступает в силу.
func (service *testService) Restart() error {
	service.restarts++

	return nil
}

// Remove автозапуск не снимает.
func (service *testService) Remove() (install.Change, error) {
	return install.Change{Done: false, Note: ""}, nil
}

// Installed — заведён ли подложный автозапуск.
func (service *testService) Installed() (bool, error) {
	return service.installed, nil
}

// TestWhitelistPrintsSortedList: без аргумента команда печатает нынешний список в порядке
// перевёрнутых меток имени.
func TestWhitelistPrintsSortedList(t *testing.T) {
	t.Parallel()

	path := writeSettings(t, "unguarded_hosts: [\"zebra.example.test\", \"*.anthropic.com\"]\n")

	out, service, err := runWhitelist(t, path, true)
	if err != nil {
		t.Fatalf("whitelist: %v", err)
	}

	if !strings.Contains(out, "exceptions (2)") {
		t.Fatalf("output %q does not head the list", out)
	}

	first := strings.Index(out, "*.anthropic.com")
	second := strings.Index(out, "zebra.example.test")

	if first < 0 || second < 0 || first > second {
		t.Fatalf("output %q is not ordered by reversed labels", out)
	}

	if service.restarts != 0 {
		t.Fatal("printing the list restarted the service")
	}
}

// TestWhitelistAddsPatternAndRestarts: шаблон дописывается в файл настроек и служба
// перезапускается сама — иначе правка не вступила бы в силу без ручных команд.
func TestWhitelistAddsPatternAndRestarts(t *testing.T) {
	t.Parallel()

	path := writeSettings(t, "unguarded_hosts: []\n")

	out, service, err := runWhitelist(t, path, true, "*.Example.TEST")
	if err != nil {
		t.Fatalf("whitelist: %v", err)
	}

	content := readSettings(t, path)
	if !strings.Contains(content, "  - \"*.example.test\"") {
		t.Fatalf("settings %q do not hold the pattern", content)
	}

	if !strings.Contains(out, "+ added to "+path+": *.example.test") {
		t.Fatalf("output %q does not report the change", out)
	}

	if !strings.Contains(out, "the service is restarted") {
		t.Fatalf("output %q does not report the restart", out)
	}

	if service.restarts != 1 {
		t.Fatalf("service restarted %d times, want once", service.restarts)
	}
}

// TestWhitelistAddsSeveralPatternsAtOnce: несколько шаблонов за вызов ложатся одной правкой,
// строки отчёта идут в порядке аргументов, а служба перезапускается ровно один раз.
func TestWhitelistAddsSeveralPatternsAtOnce(t *testing.T) {
	t.Parallel()

	path := writeSettings(t, "unguarded_hosts: []\n")

	out, service, err := runWhitelist(t, path, true, "b.test", "a.test", "*.c.test")
	if err != nil {
		t.Fatalf("whitelist: %v", err)
	}

	content := readSettings(t, path)
	for _, pattern := range []string{"\"b.test\"", "\"a.test\"", "\"*.c.test\""} {
		if !strings.Contains(content, "  - "+pattern) {
			t.Fatalf("settings %q do not hold %s", content, pattern)
		}
	}

	before := strings.Index(content, "\"b.test\"")
	middle := strings.Index(content, "\"a.test\"")
	after := strings.Index(content, "\"*.c.test\"")
	if before > middle || middle > after {
		t.Fatalf("settings %q do not keep the order of the arguments", content)
	}

	if !strings.Contains(out, "+ added to "+path+": b.test") {
		t.Fatalf("output %q does not report the first pattern", out)
	}

	for _, pattern := range []string{"b.test", "a.test", "*.c.test"} {
		if !strings.Contains(out, "+ added to "+path+": "+pattern) {
			t.Fatalf("output %q does not report %s", out, pattern)
		}
	}

	if service.restarts != 1 {
		t.Fatalf("service restarted %d times, want once for the whole edit", service.restarts)
	}
}

// TestWhitelistCollapsesDuplicateArguments: повтор шаблона в аргументах — не два пункта в
// файле, а один, и одна строка отчёта.
func TestWhitelistCollapsesDuplicateArguments(t *testing.T) {
	t.Parallel()

	path := writeSettings(t, "unguarded_hosts: []\n")

	out, service, err := runWhitelist(t, path, true, "same.test", "SAME.test", "*.same.test")
	if err != nil {
		t.Fatalf("whitelist: %v", err)
	}

	if got := strings.Count(readSettings(t, path), "  - \"same.test\"\n"); got != 1 {
		t.Fatalf("settings hold same.test %d times, want once:\n%s", got, readSettings(t, path))
	}

	if got := strings.Count(out, "+ added to "+path+": same.test\n"); got != 1 {
		t.Fatalf("output reports same.test %d times, want once:\n%s", got, out)
	}

	if service.restarts != 1 {
		t.Fatalf("service restarted %d times, want once", service.restarts)
	}
}

// TestWhitelistKeepsFileReadable: список, записанный штатным YAML без отступа (`yq`, правка
// рукой), правится тем же способом, и после правки настройки читаются — иначе команда
// отчиталась бы «в силе», а служба больше не поднялась бы.
func TestWhitelistKeepsFileReadable(t *testing.T) {
	t.Parallel()

	path := writeSettings(t, "unguarded_hosts:\n- \"first.test\"\n")

	out, service, err := runWhitelist(t, path, true, "second.test", "third.test")
	if err != nil {
		t.Fatalf("whitelist: %v", err)
	}

	if service.restarts != 1 {
		t.Fatalf("service restarted %d times, want once; output:\n%s", service.restarts, out)
	}

	settings, err := config.Load(path)
	if err != nil {
		t.Fatalf("settings after the edit do not load: %v\n%s", err, readSettings(t, path))
	}

	want := []string{"first.test", "second.test", "third.test"}
	if len(settings.UnguardedHosts) != len(want) {
		t.Fatalf("unguarded hosts %v, want %v", settings.UnguardedHosts, want)
	}

	for index, pattern := range want {
		if settings.UnguardedHosts[index] != pattern {
			t.Fatalf("unguarded hosts %v, want %v", settings.UnguardedHosts, want)
		}
	}
}

// TestWhitelistSaysAlreadyThere: уже заданный шаблон — строка «уже так» и файл не правится.
func TestWhitelistSaysAlreadyThere(t *testing.T) {
	t.Parallel()

	body := "unguarded_hosts:\n  - \"*.example.test\"\n"
	path := writeSettings(t, body)

	out, service, err := runWhitelist(t, path, true, "*.example.test")
	if err != nil {
		t.Fatalf("whitelist: %v", err)
	}

	if !strings.Contains(out, "= already set: *.example.test") {
		t.Fatalf("output %q does not say the pattern is already there", out)
	}

	if strings.Contains(out, "+ added to ") {
		t.Fatalf("output %q reports a change for a pattern already set", out)
	}

	if !strings.Contains(readSettings(t, path), body) {
		t.Fatalf("settings were rewritten:\n%s", readSettings(t, path))
	}

	if service.restarts != 0 {
		t.Fatal("the service was restarted without a change")
	}
}

// TestWhitelistMixesAlreadySetAndNew: смесь «уже есть / новый» — по уже заданному печатается
// подтверждение, по новому строка правки, файл получает только новый пункт, служба
// перезапускается один раз.
func TestWhitelistMixesAlreadySetAndNew(t *testing.T) {
	t.Parallel()

	path := writeSettings(t, "unguarded_hosts:\n  - \"*.example.test\"\n")

	out, service, err := runWhitelist(t, path, true, "*.example.test", "fresh.test")
	if err != nil {
		t.Fatalf("whitelist: %v", err)
	}

	content := readSettings(t, path)
	if got := strings.Count(content, "\"*.example.test\""); got != 1 {
		t.Fatalf("settings hold *.example.test %d times, want once:\n%s", got, content)
	}

	if !strings.Contains(content, "  - \"fresh.test\"") {
		t.Fatalf("settings %q do not hold the new pattern", content)
	}

	already := strings.Index(out, "= already set: *.example.test")
	added := strings.Index(out, "+ added to "+path+": fresh.test")

	if already < 0 || added < 0 {
		t.Fatalf("output %q does not report both patterns:\n%s", out, out)
	}

	if already > added {
		t.Fatalf("output %q reports the new pattern before the untouched one:\n%s", out, out)
	}

	if !strings.Contains(out, "the service is restarted") {
		t.Fatalf("output %q does not report the restart", out)
	}

	if service.restarts != 1 {
		t.Fatalf("service restarted %d times, want once", service.restarts)
	}
}

// TestWhitelistTellsAboutMissingService: службы нет — честная строка об этом, а не тихий
// успех: правка лежит в файле, но в силу ещё не вступила.
func TestWhitelistTellsAboutMissingService(t *testing.T) {
	t.Parallel()

	path := writeSettings(t, "unguarded_hosts: []\n")

	out, service, err := runWhitelist(t, path, false, "only.example.test")
	if err != nil {
		t.Fatalf("whitelist: %v", err)
	}

	if !strings.Contains(out, "there is no autostart") || !strings.Contains(out, "ipguard install") {
		t.Fatalf("output %q does not say the service is missing", out)
	}

	if service.restarts != 0 {
		t.Fatal("a missing service was restarted")
	}
}

// TestWhitelistWithoutAutostart: на ОС без автозапуска правка файла — всё, что команда может
// сделать, а службу владелец держит и перезапускает сам. Команда не падает на этом, но и не
// молчит: без перезапуска список ещё не в силе.
func TestWhitelistWithoutAutostart(t *testing.T) {
	t.Parallel()

	path := writeSettings(t, "unguarded_hosts: []\n")

	reader := viper.New()
	reader.Set("config", path)

	command := newWhitelist(reader, func() (guardTarget, error) {
		return guardTarget{Service: nil, Config: path}, nil
	})

	out := &bytes.Buffer{}
	command.SetOut(out)
	command.SetErr(out)
	command.SetArgs([]string{"only.example.test"})

	err := command.Execute()
	if err != nil {
		t.Fatalf("whitelist: %v", err)
	}

	text := out.String()

	if !strings.Contains(text, "+ added to "+path+": only.example.test") {
		t.Fatalf("output %q does not report the edit", text)
	}

	if !strings.Contains(text, "no autostart on this platform") || !strings.Contains(text, "restart the service") {
		t.Fatalf("output %q does not say the restart is manual", text)
	}

	if !strings.Contains(readSettings(t, path), "only.example.test") {
		t.Fatal("the pattern is not in the settings file")
	}
}

// TestTargetWithoutAutostart: ОС без автозапуска получает цель без службы и путь к файлу
// службы по умолчанию. Тест держит дефект, который иначе не виден: `install.DefaultPaths` на
// такой ОС отказывает, и команда падала бы уже после правки файла.
func TestTargetWithoutAutostart(t *testing.T) {
	t.Parallel()

	target, err := targetFor("linux")
	if err != nil {
		t.Fatalf("target for linux: %v", err)
	}

	if target.Service != nil {
		t.Fatal("a platform without autostart got a service")
	}

	if target.Config != config.DefaultPath() {
		t.Fatalf("config %q, want %q", target.Config, config.DefaultPath())
	}
}

// TestWhitelistRefusesBrokenPattern: негодный шаблон — отказ с кодом негодного вызова, без
// правки файла: по такой записи сторож пускал бы мимо проверки не то.
func TestWhitelistRefusesBrokenPattern(t *testing.T) {
	t.Parallel()

	body := "unguarded_hosts: []\n"
	path := writeSettings(t, body)
	_, service, err := runWhitelist(t, path, true, "api.*.com")

	var coded exitError
	if !errors.As(err, &coded) || coded.code != ExitUsage {
		t.Fatalf("whitelist gave %v, want exit code %d", err, ExitUsage)
	}

	if !strings.Contains(err.Error(), "api.*.com") {
		t.Fatalf("refusal %q does not name the broken pattern", err)
	}

	if !strings.Contains(readSettings(t, path), body) {
		t.Fatalf("the broken pattern changed the settings:\n%s", readSettings(t, path))
	}

	if service.restarts != 0 {
		t.Fatal("a refused pattern restarted the service")
	}
}

// TestWhitelistRefusesBrokenPatternAmongGood: негодный среди годных — отказ до первой правки:
// файл не меняется, служба не перезапускается, отказ называет именно негодный шаблон.
func TestWhitelistRefusesBrokenPatternAmongGood(t *testing.T) {
	t.Parallel()

	body := "unguarded_hosts: []\n"
	path := writeSettings(t, body)

	out, service, err := runWhitelist(t, path, true, "good.test", "api.*.com", "other.test")

	var coded exitError
	if !errors.As(err, &coded) || coded.code != ExitUsage {
		t.Fatalf("whitelist gave %v, want exit code %d", err, ExitUsage)
	}

	if !strings.Contains(coded.message, "api.*.com") {
		t.Fatalf("refusal %q does not name the broken pattern", coded.message)
	}

	if !strings.Contains(readSettings(t, path), body) {
		t.Fatalf("the good patterns were written anyway:\n%s", readSettings(t, path))
	}

	if strings.Contains(out, "+ added to ") || strings.Contains(out, "= already set:") {
		t.Fatalf("output %q reports a change that was refused:\n%s", out, out)
	}

	if service.restarts != 0 {
		t.Fatal("a refused call restarted the service")
	}
}

// runWhitelist выполняет команду белого списка с подложным автозапуском: правится тот же
// файл, который «читает служба».
func runWhitelist(t *testing.T, path string, installed bool, args ...string) (string, *testService, error) {
	t.Helper()

	return runWhitelistFor(t, path, path, installed, args...)
}

// runWhitelistFor выполняет команду с подложной целью: правится файл path, а служба читает
// файл serviceConfig.
func runWhitelistFor(
	t *testing.T, path, serviceConfig string, installed bool, args ...string,
) (string, *testService, error) {
	t.Helper()

	reader := viper.New()
	reader.Set("config", path)

	service := &testService{installed: installed, restarts: 0}

	command := newWhitelist(reader, func() (guardTarget, error) {
		return guardTarget{Service: service, Config: serviceConfig}, nil
	})

	out := &bytes.Buffer{}
	command.SetOut(out)
	command.SetErr(out)
	command.SetArgs(args)

	err := command.Execute()

	return out.String(), service, err
}

// TestWhitelistDoesNotRestartForForeignConfig: правка чужого файла (`--config`) службе не
// видна — она читает файл из каталога установки. Перезапуск и строка «в силе» здесь были бы
// ложью, поэтому команда называет файл службы и службу не трогает.
func TestWhitelistDoesNotRestartForForeignConfig(t *testing.T) {
	t.Parallel()

	path := writeSettings(t, "unguarded_hosts: []\n")
	serviceConfig := filepath.Join(t.TempDir(), "ipguard.yaml")

	out, service, err := runWhitelistFor(t, path, serviceConfig, true, "only.example.test")
	if err != nil {
		t.Fatalf("whitelist: %v", err)
	}

	if !strings.Contains(out, serviceConfig) || !strings.Contains(out, "will not take effect") {
		t.Fatalf("output %q does not name the file the service reads", out)
	}

	if strings.Contains(out, "in force") {
		t.Fatalf("output %q claims the edit is in force", out)
	}

	if service.restarts != 0 {
		t.Fatalf("the service was restarted for a foreign file %d times", service.restarts)
	}

	if !strings.Contains(readSettings(t, path), "only.example.test") {
		t.Fatal("the pattern was not written to the foreign file")
	}
}

// TestWhitelistBeforeInstall: файла настроек ещё нет — встроенного ожидаемого адреса тоже, и
// отказ называет установку, а не голое «no such file».
func TestWhitelistBeforeInstall(t *testing.T) {
	t.Parallel()

	path := filepath.Join(t.TempDir(), "ipguard.yaml")

	out, service, err := runWhitelist(t, path, false, "only.example.test")
	if err == nil {
		t.Fatalf("whitelist without settings succeeded, output %q", out)
	}

	if !strings.Contains(err.Error(), "expected_ip is not set") || !strings.Contains(err.Error(), "ipguard install") {
		t.Fatalf("refusal %q does not tell to install first", err)
	}

	if service.restarts != 0 {
		t.Fatal("the service was restarted without settings")
	}
}

// writeSettings кладёт файл настроек теста: ожидаемый адрес в нём свой — встроенного нет.
func writeSettings(t *testing.T, body string) string {
	t.Helper()

	path := filepath.Join(t.TempDir(), "ipguard.yaml")

	err := os.WriteFile(path, []byte("expected_ip: 203.0.113.7\nsecret: cli-secret\n"+body), 0o600)
	if err != nil {
		t.Fatalf("write settings: %v", err)
	}

	return path
}

// readSettings читает файл настроек теста.
func readSettings(t *testing.T, path string) string {
	t.Helper()

	content, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read settings: %v", err)
	}

	return string(content)
}
