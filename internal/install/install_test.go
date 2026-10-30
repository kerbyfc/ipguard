package install_test

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/kerbyfc/ipguard/internal/config"
	"github.com/kerbyfc/ipguard/internal/install"
	"github.com/kerbyfc/ipguard/internal/proxy"
)

// TestInstallCreatesEverything: первая установка кладёт бинарник и запись автозапуска.
func TestInstallCreatesEverything(t *testing.T) {
	t.Parallel()

	stand := newStand(t)

	err := install.Install(t.Context(), stand.options)
	if err != nil {
		t.Fatalf("install: %v", err)
	}

	binary := readTestFile(t, stand.paths.Binary)
	if binary != "binary-one" {
		t.Fatalf("installed binary %q, want the source copied", binary)
	}

	if stand.service.ensured != 1 || stand.service.binary != stand.paths.Binary {
		t.Fatalf("autostart ensured %d times for %q", stand.service.ensured, stand.service.binary)
	}
}

// TestInstallWritesSettings: настройки создаются с секретом, правами 0600 и пустым белым
// списком: под вердиктом всё, кроме хоста проверки и локальных целей.
func TestInstallWritesSettings(t *testing.T) {
	t.Parallel()

	stand := newStand(t)

	err := install.Install(t.Context(), stand.options)
	if err != nil {
		t.Fatalf("install: %v", err)
	}

	settings := readTestFile(t, stand.paths.Config)
	if !strings.Contains(settings, "expected_ip: 203.0.113.9") || !strings.Contains(settings, testSecret) {
		t.Fatalf("settings file %q has no expected IP or secret", settings)
	}

	loaded, err := config.Load(stand.paths.Config)
	if err != nil {
		t.Fatalf("installed settings do not load: %v", err)
	}

	if len(loaded.UnguardedHosts) != 0 {
		t.Fatalf("installed unguarded hosts %v, want an empty whitelist", loaded.UnguardedHosts)
	}

	if !strings.Contains(settings, "unguarded_hosts: []") {
		t.Fatalf("settings file %q has no whitelist key", settings)
	}

	requireOwnerOnly(t, stand.paths.Config, 0o600)
}

// TestInstallLeavesServiceRunning: обещание установки — после неё сторож слушает порт.
// Запись автозапуска процесс не поднимает (задача планировщика Windows ждёт входа в систему),
// поэтому установка поднимает его сама — и на свежей машине, и когда менять нечего, а служба
// вышла.
func TestInstallLeavesServiceRunning(t *testing.T) {
	t.Parallel()

	stand := newStand(t)

	err := install.Install(t.Context(), stand.options)
	if err != nil {
		t.Fatalf("first install: %v", err)
	}

	if !stand.service.running {
		t.Fatal("install finished with the service down: nobody listens on the port")
	}

	stand.service.running = false
	stand.out.Reset()

	err = install.Install(t.Context(), stand.options)
	if err != nil {
		t.Fatalf("install over a settled machine with a dead service: %v", err)
	}

	if !stand.service.running {
		t.Fatalf("install left the service down:\n%s", stand.out.String())
	}
}

// TestInstallReportsEveryStep: отчёт первой установки отмечает каждый шаг сделанным, называет
// механизм автозапуска и кончается вердиктом живого сервиса.
func TestInstallReportsEveryStep(t *testing.T) {
	t.Parallel()

	stand := newStand(t)

	err := install.Install(t.Context(), stand.options)
	if err != nil {
		t.Fatalf("install: %v", err)
	}

	report := stand.out.String()
	for _, step := range []string{"directory", "binary", "settings", "autostart", "service", "probe"} {
		if stepMark(t, report, step) != "+" {
			t.Fatalf("step %q is not done on a fresh install:\n%s", step, report)
		}
	}

	// Шаг белого списка идёт до чтения настроек — иначе снятый ключ валил бы загрузку, —
	// и на свежей машине ему править нечего: список приходит в новом файле из шаблона.
	if stepMark(t, report, "hosts") != "=" || !strings.Contains(report, "the whitelist comes from the template") {
		t.Fatalf("step \"hosts\" does not explain the fresh install:\n%s", report)
	}

	if !strings.Contains(report, "verdict allowed") {
		t.Fatalf("report has no verdict of the live service:\n%s", report)
	}

	if !strings.Contains(report, stand.service.Describe()) {
		t.Fatalf("report does not name the autostart mechanism:\n%s", report)
	}
}

// TestInstallSecondRunChangesNothing: уже установленное не переделывается — каждый шаг
// отвечает подтверждением, а файл настроек с секретом остаётся прежним.
func TestInstallSecondRunChangesNothing(t *testing.T) {
	t.Parallel()

	stand := newStand(t)

	err := install.Install(t.Context(), stand.options)
	if err != nil {
		t.Fatalf("first install: %v", err)
	}

	first := readTestFile(t, stand.paths.Config)

	stand.service.restarts = 0
	stand.service.starts = 0
	stand.out.Reset()

	err = install.Install(t.Context(), stand.options)
	if err != nil {
		t.Fatalf("second install: %v", err)
	}

	if readTestFile(t, stand.paths.Config) != first {
		t.Fatal("second install rewrote the settings file with its secret")
	}

	report := stand.out.String()
	for _, step := range []string{"directory", "binary", "settings", "hosts", "autostart"} {
		if stepMark(t, report, step) != "=" {
			t.Fatalf("step %q redone on the second install:\n%s", step, report)
		}
	}

	if stand.service.restarts != 0 {
		t.Fatalf("service restarted %d times without a new binary", stand.service.restarts)
	}

	if stand.service.starts != 1 || !strings.Contains(report, "started") {
		t.Fatalf("second install started the service %d times:\n%s", stand.service.starts, report)
	}
}

// TestInstallRestartsForNewBinary: новый бинарник работающая служба подхватывает только
// перезапуском, поэтому установка его делает — и только в этом случае.
func TestInstallRestartsForNewBinary(t *testing.T) {
	t.Parallel()

	stand := newStand(t)

	err := install.Install(t.Context(), stand.options)
	if err != nil {
		t.Fatalf("first install: %v", err)
	}

	writeTestFile(t, stand.self, "binary-two")
	stand.service.restarts = 0
	stand.service.starts = 0
	stand.out.Reset()

	err = install.Install(t.Context(), stand.options)
	if err != nil {
		t.Fatalf("second install: %v", err)
	}

	if readTestFile(t, stand.paths.Binary) != "binary-two" {
		t.Fatal("new binary was not installed")
	}

	if stand.service.restarts != 1 || stand.service.starts != 0 {
		t.Fatalf(
			"service restarted %d times and started %d, want one restart after the binary changed",
			stand.service.restarts, stand.service.starts,
		)
	}

	report := stand.out.String()
	if stepMark(t, report, "service") != "+" || !strings.Contains(report, "restarted onto the new binary") {
		t.Fatalf("restart is not reported:\n%s", report)
	}
}

// TestInstallClosesOpenAccess: каталог и настройки прежней установки открыты другим
// пользователям машины — установка закрывает их и говорит об этом шагом «доступ». Молча
// подтвердить открытый секрет она не вправе.
func TestInstallClosesOpenAccess(t *testing.T) {
	t.Parallel()

	stand := newStand(t)
	writeTestFile(t, stand.paths.Config, "expected_ip: 198.51.100.7\nsecret: old-secret\n")
	openTestPath(t, stand.paths.Dir, 0o755)
	openTestPath(t, stand.paths.Config, 0o644)

	stand.options.ExpectedIP = ""

	err := install.Install(t.Context(), stand.options)
	if err != nil {
		t.Fatalf("install over an open install directory: %v", err)
	}

	report := stand.out.String()
	if stepMark(t, report, "access") != "+" {
		t.Fatalf("report does not say the access was closed:\n%s", report)
	}

	requireOwnerOnly(t, stand.paths.Dir, 0o700)
	requireOwnerOnly(t, stand.paths.Config, 0o600)
}

// TestInstallConfirmsClosedAccess: каталог и настройки уже закрыты — шаг подтверждает доступ
// и ничего не правит.
func TestInstallConfirmsClosedAccess(t *testing.T) {
	t.Parallel()

	stand := newStand(t)

	err := install.Install(t.Context(), stand.options)
	if err != nil {
		t.Fatalf("install: %v", err)
	}

	stand.out.Reset()

	err = install.Install(t.Context(), stand.options)
	if err != nil {
		t.Fatalf("second install: %v", err)
	}

	report := stand.out.String()
	if stepMark(t, report, "access") != "=" {
		t.Fatalf("settled access is not confirmed:\n%s", report)
	}
}

// TestInstallKeepsExistingSettings: лежащий файл настроек не переписывается — в нём секрет и
// решения владельца; установка только дописывает недостающий белый список.
func TestInstallKeepsExistingSettings(t *testing.T) {
	t.Parallel()

	stand := newStand(t)
	existing := "expected_ip: 198.51.100.7\nsecret: old-secret\n"
	writeTestFile(t, stand.paths.Config, existing)

	stand.options.ExpectedIP = ""

	err := install.Install(t.Context(), stand.options)
	if err != nil {
		t.Fatalf("install over existing settings: %v", err)
	}

	updated := readTestFile(t, stand.paths.Config)
	if !strings.HasPrefix(updated, existing) {
		t.Fatalf("existing settings were rewritten:\n%s", updated)
	}

	if !strings.Contains(updated, "unguarded_hosts: []") {
		t.Fatalf("install did not append the whitelist key:\n%s", updated)
	}

	report := stand.out.String()
	if stepMark(t, report, "settings") != "=" || !strings.Contains(report, "198.51.100.7") {
		t.Fatalf("report does not confirm the existing settings:\n%s", report)
	}

	if stepMark(t, report, "hosts") != "+" || !strings.Contains(report, "added") {
		t.Fatalf("report does not say the list was appended:\n%s", report)
	}
}

// TestInstallKeepsExistingUnguardedHosts: белый список владельца — его решение; установка не
// трогает его и на повторном запуске только подтверждает.
func TestInstallKeepsExistingUnguardedHosts(t *testing.T) {
	t.Parallel()

	stand := newStand(t)
	existing := "expected_ip: 198.51.100.7\nsecret: old-secret\nunguarded_hosts: [\"only.example.test\"]\n"
	writeTestFile(t, stand.paths.Config, existing)

	stand.options.ExpectedIP = ""

	err := install.Install(t.Context(), stand.options)
	if err != nil {
		t.Fatalf("install over a custom whitelist: %v", err)
	}

	if readTestFile(t, stand.paths.Config) != existing {
		t.Fatal("install rewrote the whitelist of the owner")
	}

	report := stand.out.String()
	if stepMark(t, report, "hosts") != "=" || !strings.Contains(report, "already set") {
		t.Fatalf("report does not confirm the existing list:\n%s", report)
	}
}

// TestInstallRewritesGuardedHosts: снятая настройка — отказ загрузки, поэтому установка
// переписывает ключ сама и говорит об этом строкой шага. Иначе сторож не поднялся бы вовсе,
// а владелец правил бы файл руками.
func TestInstallRewritesGuardedHosts(t *testing.T) {
	t.Parallel()

	stand := newStand(t)
	existing := "expected_ip: 203.0.113.9\nsecret: old-secret\n" +
		"guarded_hosts:\n  - \"*.anthropic.com\"\n"
	writeTestFile(t, stand.paths.Config, existing)

	stand.options.ExpectedIP = ""

	err := install.Install(t.Context(), stand.options)
	if err != nil {
		t.Fatalf("install over the removed key: %v", err)
	}

	updated := readTestFile(t, stand.paths.Config)
	if strings.Contains("\n"+updated, "\nguarded_hosts") || strings.Contains(updated, "anthropic.com") {
		t.Fatalf("the removed key survived:\n%s", updated)
	}

	if !strings.Contains(updated, "unguarded_hosts: []") {
		t.Fatalf("the whitelist key was not written:\n%s", updated)
	}

	if !strings.Contains(updated, "secret: old-secret") {
		t.Fatalf("the secret was lost:\n%s", updated)
	}

	loaded, err := config.Load(stand.paths.Config)
	if err != nil {
		t.Fatalf("settings after the rewrite do not load: %v", err)
	}

	if len(loaded.UnguardedHosts) != 0 {
		t.Fatalf("unguarded hosts %v, want an empty whitelist", loaded.UnguardedHosts)
	}

	report := stand.out.String()
	if stepMark(t, report, "hosts") != "+" || !strings.Contains(report, "guarded_hosts removed") {
		t.Fatalf("report does not say the key was rewritten:\n%s", report)
	}
}

// TestInstallRefusesContradictingExpectedIP: просьба владельца расходится с лежащим файлом —
// отказ, а не тихая правка файла или тихое пренебрежение флагом.
func TestInstallRefusesContradictingExpectedIP(t *testing.T) {
	t.Parallel()

	stand := newStand(t)
	existing := "expected_ip: 198.51.100.7\nsecret: old-secret\n"
	writeTestFile(t, stand.paths.Config, existing)

	err := install.Install(t.Context(), stand.options)
	if !errors.Is(err, install.ErrInstall) {
		t.Fatalf("install gave %v, want an install error", err)
	}

	message := err.Error()
	if !strings.Contains(message, "198.51.100.7") || !strings.Contains(message, "203.0.113.9") {
		t.Fatalf("error %q does not name both addresses", message)
	}

	// Белый список шаг до чтения настроек дописать успел — и сказал об этом строкой; решения
	// владельца при этом на месте, переписать их отказ не может.
	kept := readTestFile(t, stand.paths.Config)
	if !strings.HasPrefix(kept, existing) || !strings.Contains(kept, "unguarded_hosts: []") {
		t.Fatalf("refused install rewrote the settings:\n%s", kept)
	}

	if stand.service.ensured != 0 {
		t.Fatal("refused install still touched the autostart")
	}
}

// TestInstallRefusesNotConfirmedDetection: найденный адрес без `--yes` и без терминала —
// отказ с подсказкой, какие флаги есть.
func TestInstallRefusesNotConfirmedDetection(t *testing.T) {
	t.Parallel()

	stand := newStand(t)
	stand.options.ExpectedIP = ""
	stand.options.Detect = detected("198.51.100.4")

	err := install.Install(t.Context(), stand.options)
	if !errors.Is(err, install.ErrInstall) {
		t.Fatalf("install gave %v, want an install error", err)
	}

	if !strings.Contains(err.Error(), "--yes") {
		t.Fatalf("error %q does not name the flags", err)
	}

	_, statErr := os.Stat(stand.paths.Config)
	if !os.IsNotExist(statErr) {
		t.Fatalf("stat settings gave %v, want no settings written", statErr)
	}
}

// TestInstallConfirmsDetectedIP: в терминале владелец подтверждает найденный адрес, и он
// становится ожидаемым.
func TestInstallConfirmsDetectedIP(t *testing.T) {
	t.Parallel()

	stand := newStand(t)
	stand.options.ExpectedIP = ""
	stand.options.Detect = detected("198.51.100.4")
	stand.options.Interactive = true
	stand.options.In = strings.NewReader("y\n")

	err := install.Install(t.Context(), stand.options)
	if err != nil {
		t.Fatalf("install with a confirmed address: %v", err)
	}

	settings := readTestFile(t, stand.paths.Config)
	if !strings.Contains(settings, "expected_ip: 198.51.100.4") {
		t.Fatalf("settings %q do not hold the confirmed address", settings)
	}
}

// TestInstallRefusesDeclinedIP: ответ «нет» — отказ, а не установка со встроенным адресом.
func TestInstallRefusesDeclinedIP(t *testing.T) {
	t.Parallel()

	stand := newStand(t)
	stand.options.ExpectedIP = ""
	stand.options.Detect = detected("198.51.100.4")
	stand.options.Interactive = true
	stand.options.In = strings.NewReader("n\n")

	err := install.Install(t.Context(), stand.options)
	if !errors.Is(err, install.ErrInstall) {
		t.Fatalf("install gave %v, want an install error", err)
	}
}

// TestInstallRefusesBadExpectedIP: `--expected-ip` не адрес — отказ до правки файлов.
func TestInstallRefusesBadExpectedIP(t *testing.T) {
	t.Parallel()

	stand := newStand(t)
	stand.options.ExpectedIP = "not-an-ip"

	err := install.Install(t.Context(), stand.options)
	if !errors.Is(err, install.ErrInstall) {
		t.Fatalf("install gave %v, want an install error", err)
	}
}

// TestInstallReportsBlockedVerdict: сервис закрывает трафик — установка это печатает и
// кончается без ошибки: сторож поставлен, а вердикт зависит от сети.
func TestInstallReportsBlockedVerdict(t *testing.T) {
	t.Parallel()

	stand := newStand(t)
	stand.options.Probe = blockedProbe

	err := install.Install(t.Context(), stand.options)
	if err != nil {
		t.Fatalf("install with a blocking verdict: %v", err)
	}

	report := stand.out.String()
	if !strings.Contains(report, "TRAFFIC IS BLOCKED") || !strings.Contains(report, "external IP is not the expected one") {
		t.Fatalf("report does not say the traffic is blocked:\n%s", report)
	}

	if !strings.Contains(report, "last error: dial tcp: timeout") {
		t.Fatalf("report does not name the last error:\n%s", report)
	}
}

// TestInstallFailsWithoutListener: автозапуск не поднял слушателя — отказ, называющий
// журнал: причина лежит там.
func TestInstallFailsWithoutListener(t *testing.T) {
	t.Parallel()

	stand := newStand(t)
	stand.options.Await = func(_ context.Context, address string) error {
		return fmt.Errorf("%w: nobody listens on %s", install.ErrInstall, address)
	}

	err := install.Install(t.Context(), stand.options)
	if !errors.Is(err, install.ErrInstall) {
		t.Fatalf("install gave %v, want an install error", err)
	}

	if !strings.Contains(err.Error(), "journal") {
		t.Fatalf("error %q does not name the journal", err)
	}
}

// TestInstallFailsOnUnansweredProbe: служба слушает, но вердикта не дала — установка не
// проверена, и это отказ, а не код 0: 407 от своего же прокси, таймаут и битый ответ —
// поломки установки.
func TestInstallFailsOnUnansweredProbe(t *testing.T) {
	t.Parallel()

	stand := newStand(t)
	stand.options.Probe = func(_ context.Context, _ config.Settings) (proxy.StatusView, error) {
		return proxy.StatusView{}, errFake
	}

	err := install.Install(t.Context(), stand.options)
	if !errors.Is(err, install.ErrInstall) {
		t.Fatalf("install gave %v, want an install error", err)
	}

	report := stand.out.String()
	if !strings.Contains(report, "gave no verdict") {
		t.Fatalf("report does not name the failed probe:\n%s", report)
	}
}

// TestUninstallKeepsSettingsAndBinary: снятие убирает только автозапуск — в настройках
// секрет, в журнале история отказов, и сторож их не трёт.
func TestUninstallKeepsSettingsAndBinary(t *testing.T) {
	t.Parallel()

	stand := newStand(t)

	err := install.Install(t.Context(), stand.options)
	if err != nil {
		t.Fatalf("install: %v", err)
	}

	stand.out.Reset()

	err = install.Uninstall(stand.options)
	if err != nil {
		t.Fatalf("uninstall: %v", err)
	}

	if stand.service.removed != 1 {
		t.Fatalf("autostart removed %d times, want once", stand.service.removed)
	}

	for _, path := range []string{stand.paths.Config, stand.paths.Binary} {
		_, statErr := os.Stat(path)
		if statErr != nil {
			t.Fatalf("stat %s after uninstall: %v", path, statErr)
		}
	}

	report := stand.out.String()
	if !strings.Contains(report, stand.service.Describe()) {
		t.Fatalf("report does not name the autostart mechanism:\n%s", report)
	}

	if !strings.Contains(report, "ipguard disable") {
		t.Fatalf("report does not say how to drop the proxy from claude:\n%s", report)
	}
}

// TestPathsPerOS: адреса установки — те же, что читает служба; ОС без автозапуска — отказ, а
// не установка без автозапуска.
func TestPathsPerOS(t *testing.T) {
	t.Parallel()

	home := t.TempDir()

	mac, err := install.NewPaths(install.GOOSDarwin, home)
	if err != nil {
		t.Fatalf("darwin paths: %v", err)
	}

	wantUnit := filepath.Join(home, "Library", "LaunchAgents", install.Label+".plist")
	if mac.Unit != wantUnit {
		t.Fatalf("launchd unit %q, want %q", mac.Unit, wantUnit)
	}

	if mac.Binary != filepath.Join(home, ".local", "bin", install.BinaryName) {
		t.Fatalf("darwin binary %q", mac.Binary)
	}

	windows, err := install.NewPaths(install.GOOSWindows, home)
	if err != nil {
		t.Fatalf("windows paths: %v", err)
	}

	if !strings.HasSuffix(windows.Binary, ".exe") || windows.Unit != "" {
		t.Fatalf("windows binary %q unit %q", windows.Binary, windows.Unit)
	}

	_, err = install.NewPaths("linux", home)
	if !errors.Is(err, install.ErrInstall) {
		t.Fatalf("paths for linux gave %v, want an install error", err)
	}
}
