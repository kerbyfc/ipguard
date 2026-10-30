package config_test

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/kerbyfc/ipguard/internal/config"
)

const goodSettings = `
expected_ip: 203.0.113.7
check_url: https://icanhazip.test/
unguarded_hosts: ["*.anthropic.com", "example.test"]
attempt_timeout: 5s
retry_delays: [1s, 3s]
budget: 60s
listen_address: 127.0.0.1
listen_port: 18787
secret: file-secret
upstream_proxy: http://127.0.0.1:3128
log_path: /tmp/ipguard-test.log
`

// TestMissingFileRefusesWithoutExpectedIP: встроенного ожидаемого адреса нет — без файла
// настройки не проходят проверку, и отказ называет установку, а не формат пустой строки.
func TestMissingFileRefusesWithoutExpectedIP(t *testing.T) {
	t.Parallel()

	_, err := config.Load(filepath.Join(t.TempDir(), "absent.yaml"))
	if !errors.Is(err, config.ErrSettings) {
		t.Fatalf("load without a file gave %v, want a settings error", err)
	}

	if !strings.Contains(err.Error(), "expected_ip is not set") || !strings.Contains(err.Error(), "ipguard install") {
		t.Fatalf("refusal %q does not tell how to set the expected IP", err)
	}
}

// TestMissingFileKeepsEmptyWhitelist: встроенный белый список пуст — под вердиктом каждый
// хост, кроме хоста проверки и локальных целей, которые исключены в коде.
func TestMissingFileKeepsEmptyWhitelist(t *testing.T) {
	t.Parallel()

	settings := config.Defaults()

	if len(settings.UnguardedHosts) != 0 {
		t.Fatalf("default unguarded hosts %v, want none", settings.UnguardedHosts)
	}
}

// TestMissingFileKeepsSeenHostsPath: файл встреченных хостов лежит рядом с журналом, в
// каталоге установки.
func TestMissingFileKeepsSeenHostsPath(t *testing.T) {
	t.Parallel()

	settings := config.Defaults()

	want := filepath.Join(config.DefaultDir(), config.SeenHostsFileName)
	if settings.SeenHostsPath != want {
		t.Fatalf("seen hosts path %q, want %q", settings.SeenHostsPath, want)
	}
}

// TestDefaultsHoldContractedTimings: встроенные значения нынешнего контракта — источник,
// тайминги и бюджет; ожидаемого адреса среди них нет.
func TestDefaultsHoldContractedTimings(t *testing.T) {
	t.Parallel()

	settings := config.Defaults()

	if settings.ExpectedIP != "" {
		t.Fatalf("default expected IP %q, want none", settings.ExpectedIP)
	}

	if settings.CheckURL != config.DefaultCheckURL {
		t.Fatalf("check URL %q, want %q", settings.CheckURL, config.DefaultCheckURL)
	}

	if settings.AttemptTimeout != config.DefaultAttemptTimeout || settings.Budget != config.DefaultBudget {
		t.Fatalf(
			"attempt timeout %s budget %s, want %s and %s",
			settings.AttemptTimeout, settings.Budget, config.DefaultAttemptTimeout, config.DefaultBudget,
		)
	}

	if settings.AttemptTimeout <= 10*time.Second {
		t.Fatalf("attempt timeout %s did not grow beyond the old 10s", settings.AttemptTimeout)
	}
}

// TestUnguardedHostsSet: установка различает дописанный ею список и список владельца, в том
// числе пустой — его она тоже не переписывает.
func TestUnguardedHostsSet(t *testing.T) {
	t.Parallel()

	for _, body := range []string{"unguarded_hosts: [\"*.anthropic.com\"]\n", "unguarded_hosts: []\n"} {
		set, err := config.UnguardedHostsSet(write(t, body))
		if err != nil {
			t.Fatalf("unguarded hosts set: %v", err)
		}

		if !set {
			t.Fatalf("unguarded_hosts key was not found in %q", body)
		}
	}

	set, err := config.UnguardedHostsSet(write(t, "expected_ip: 203.0.113.7\n"))
	if err != nil {
		t.Fatalf("unguarded hosts absent: %v", err)
	}

	if set {
		t.Fatal("absent unguarded_hosts key was reported as set")
	}
}

// TestLoadRefusesGuardedHosts: оставшийся в файле ключ снятой настройки — отказ с причиной.
// Молча принять его нельзя: прежний список охраны, прочитанный как белый, пускал бы мимо
// проверки ровно хосты Claude.
func TestLoadRefusesGuardedHosts(t *testing.T) {
	t.Parallel()

	_, err := config.Load(write(t, "guarded_hosts: [\"*.anthropic.com\"]\n"))
	if err == nil {
		t.Fatal("settings with guarded_hosts were accepted")
	}

	if !errors.Is(err, config.ErrGuardedHostsRemoved) {
		t.Fatalf("load gave %v, want the removed-key refusal", err)
	}

	if !strings.Contains(err.Error(), "unguarded_hosts") {
		t.Fatalf("refusal %q does not name the new setting", err)
	}
}

// TestSecretRequiredForListener: без секрета слушатель не поднимается.
func TestSecretRequiredForListener(t *testing.T) {
	t.Parallel()

	settings := config.Defaults()

	err := settings.RequireSecret()
	if !errors.Is(err, config.ErrSettings) {
		t.Fatalf("empty secret gave %v, want a settings error", err)
	}

	settings.Secret = "secret"

	err = settings.RequireSecret()
	if err != nil {
		t.Fatalf("secret rejected: %v", err)
	}
}

func TestGoodFileRead(t *testing.T) {
	t.Parallel()

	settings := loadGood(t)

	if settings.ExpectedIP != "203.0.113.7" || settings.Secret != "file-secret" {
		t.Fatalf("expected IP %q secret %q", settings.ExpectedIP, settings.Secret)
	}

	if len(settings.UnguardedHosts) != 2 || settings.UnguardedHosts[1] != "example.test" {
		t.Fatalf("unguarded hosts %v, want the file list", settings.UnguardedHosts)
	}
}

func TestGoodFileReadTimings(t *testing.T) {
	t.Parallel()

	settings := loadGood(t)

	if settings.AttemptTimeout != 5*time.Second {
		t.Fatalf("attempt timeout %s, want 5s", settings.AttemptTimeout)
	}

	if len(settings.RetryDelays) != 2 || settings.RetryDelays[1] != 3*time.Second {
		t.Fatalf("retry delays %v, want [1s 3s]", settings.RetryDelays)
	}

	if settings.ListenAddr() != "127.0.0.1:18787" {
		t.Fatalf("listen addr %q", settings.ListenAddr())
	}
}

// loadGood читает файл настроек, который проходит проверку целиком.
func loadGood(t *testing.T) config.Settings {
	t.Helper()

	settings, err := config.Load(write(t, goodSettings))
	if err != nil {
		t.Fatalf("load: %v", err)
	}

	return settings
}

// TestBrokenFileFails: битый файл — отказ с причиной, а не тихий откат к значениям по умолчанию.
func TestBrokenFileFails(t *testing.T) {
	t.Parallel()

	cases := map[string]struct {
		body string
		want string
		// full — содержимое файла целиком, без подставленного ожидаемого адреса: так
		// проверяется и его собственный отказ.
		full bool
	}{
		"нет ожидаемого адреса":    {body: "secret: abc\n", want: "expected_ip is not set", full: true},
		"битый yaml":               {body: "expected_ip: [unclosed\n", want: "ipguard.yaml", full: true},
		"лишнее поле":              {body: "expectd_ip: 203.0.113.7\n", want: "expectd_ip"},
		"не адрес":                 {body: "expected_ip: not-an-ip\n", want: "expected_ip", full: true},
		"пустое расписание":        {body: "retry_delays: []\n", want: "retry_delays"},
		"отрицательная пауза":      {body: "retry_delays: [-1s]\n", want: "retry_delays[0]"},
		"бюджет короче попытки":    {body: "budget: 1s\n", want: "budget"},
		"звезда не в начале":       {body: "unguarded_hosts: [api.*.com]\n", want: "unguarded_hosts"},
		"звезда без точки":         {body: "unguarded_hosts: [\"*anthropic.com\"]\n", want: "unguarded_hosts"},
		"снятый ключ охраны":       {body: "guarded_hosts: [\"a.test\"]\n", want: "guarded_hosts"},
		"пустой файл накопленного": {body: `seen_hosts_path: ""`, want: "seen_hosts_path"},
		"слушатель наружу":         {body: "listen_address: 8.8.8.8\n", want: "loopback"},
		"порт вне диапазона":       {body: "listen_port: 70000\n", want: "listen_port"},
		"верхний прокси tls":       {body: "upstream_proxy: https://127.0.0.1:3128\n", want: "upstream_proxy"},
		"пустой журнал":            {body: `log_path: ""`, want: "log_path"},
		"журнал без предела":       {body: "log_max_bytes: 0\n", want: "log_max_bytes"},
		"журнал без файлов":        {body: "log_keep: 0\n", want: "log_keep"},
	}

	for name, item := range cases {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			body := item.body
			if !item.full {
				body = "expected_ip: 203.0.113.7\n" + body
			}

			_, err := config.Load(write(t, body))
			if !errors.Is(err, config.ErrSettings) {
				t.Fatalf("load gave %v, want a settings error", err)
			}

			if !strings.Contains(err.Error(), item.want) {
				t.Fatalf("error %q does not name %q", err, item.want)
			}
		})
	}
}

// TestRemovedVerdictTTLIsRejected: ключ снятой настройки не игнорируется молча — отказ
// называет настройку и говорит, что она снята.
func TestRemovedVerdictTTLIsRejected(t *testing.T) {
	t.Parallel()

	_, err := config.Load(write(t, "verdict_ttl: 10m\n"))
	if !errors.Is(err, config.ErrSettings) || !errors.Is(err, config.ErrVerdictTTLRemoved) {
		t.Fatalf("load gave %v, want a settings error naming the removed setting", err)
	}

	if !strings.Contains(err.Error(), "verdict_ttl was removed") {
		t.Fatalf("error %q does not say the setting was removed", err)
	}
}

// TestHomeExpanded: `~` в пути журнала и в пути самого файла настроек раскрывается — у launchd
// и планировщика Windows рабочий каталог не домашний. Параллельным тест быть не может: t.Setenv.
func TestHomeExpanded(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("USERPROFILE", home)

	body := "expected_ip: 203.0.113.7\nlog_path: ~/logs/proxy.log\n"

	err := os.WriteFile(filepath.Join(home, "ipguard.yaml"), []byte(body), 0o600)
	if err != nil {
		t.Fatalf("write settings: %v", err)
	}

	settings, err := config.Load("~/ipguard.yaml")
	if err != nil {
		t.Fatalf("load from ~: %v", err)
	}

	want := filepath.Join(home, "logs", "proxy.log")
	if settings.LogPath != want {
		t.Fatalf("log path %q, want %q", settings.LogPath, want)
	}
}

// TestHomeExpansionRejectsOtherUser: `~user` — отказ, а не каталог, созданный рядом.
func TestHomeExpansionRejectsOtherUser(t *testing.T) {
	t.Parallel()

	_, err := config.ExpandHome("~someone/logs")
	if !errors.Is(err, config.ErrSettings) {
		t.Fatalf("expand gave %v, want a settings error", err)
	}
}

func write(t *testing.T, body string) string {
	t.Helper()

	path := filepath.Join(t.TempDir(), "ipguard.yaml")

	err := os.WriteFile(path, []byte(body), 0o600)
	if err != nil {
		t.Fatalf("write settings: %v", err)
	}

	return path
}
