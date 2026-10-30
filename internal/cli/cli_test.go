package cli_test

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/kerbyfc/ipguard/internal/cli"
	"github.com/kerbyfc/ipguard/internal/config"
)

// TestServeRejectsBrokenSettings: битый файл настроек — выход с ненулевым кодом, а не работа
// по встроенным значениям.
func TestServeRejectsBrokenSettings(t *testing.T) {
	t.Parallel()

	path := filepath.Join(t.TempDir(), "ipguard.yaml")

	err := os.WriteFile(path, []byte("listen_port: 70000\n"), 0o600)
	if err != nil {
		t.Fatalf("write settings: %v", err)
	}

	code := cli.Run([]string{"serve", "--config", path})
	if code != cli.ExitUsage {
		t.Fatalf("exit code %d on broken settings, want %d", code, cli.ExitUsage)
	}
}

// TestDisableRejectsRemovedVerdictTTL: оставшийся в файле ключ снятой настройки — код 2, а не
// тихая работа. Причину называет проверка настроек; здесь важен отказ команды до правки файла
// claude.
func TestDisableRejectsRemovedVerdictTTL(t *testing.T) {
	t.Parallel()

	directory := t.TempDir()
	path := filepath.Join(directory, "ipguard.yaml")

	err := os.WriteFile(path, []byte("expected_ip: 203.0.113.7\nverdict_ttl: 10m\n"), 0o600)
	if err != nil {
		t.Fatalf("write settings: %v", err)
	}

	code := cli.Run([]string{
		"disable", "--config", path, "--settings", filepath.Join(directory, "settings.json"),
	})
	if code != cli.ExitUsage {
		t.Fatalf("exit code %d on removed verdict_ttl, want %d", code, cli.ExitUsage)
	}
}

// TestServeRejectsMissingSecret: без секрета прокси не поднимается — иначе порт стоял бы
// открытым для любого локального процесса. Параллельным этот тест быть не может: t.Setenv.
func TestServeRejectsMissingSecret(t *testing.T) {
	t.Setenv(config.SecretEnv, "")

	path := filepath.Join(t.TempDir(), "ipguard.yaml")

	err := os.WriteFile(path, []byte("expected_ip: 203.0.113.7\n"), 0o600)
	if err != nil {
		t.Fatalf("write settings: %v", err)
	}

	code := cli.Run([]string{"serve", "--config", path})
	if code != cli.ExitUsage {
		t.Fatalf("exit code %d without a secret, want %d", code, cli.ExitUsage)
	}
}

func TestVersion(t *testing.T) {
	t.Parallel()

	code := cli.Run([]string{"version"})
	if code != 0 {
		t.Fatalf("exit code %d, want 0", code)
	}
}

func TestUnknownCommand(t *testing.T) {
	t.Parallel()

	code := cli.Run([]string{"stop-the-world"})
	if code != cli.ExitUsage {
		t.Fatalf("exit code %d, want %d", code, cli.ExitUsage)
	}
}

// TestEnableAndDisableClaudeSettings: прокси прописывается в настройки Claude Code по
// нынешнему адресу и порту сторожа и снимается тем же способом.
func TestEnableAndDisableClaudeSettings(t *testing.T) {
	t.Parallel()

	directory := t.TempDir()
	configPath := filepath.Join(directory, "ipguard.yaml")
	claudePath := filepath.Join(directory, "settings.json")

	err := os.WriteFile(configPath, []byte("expected_ip: 203.0.113.7\nsecret: cli-secret\nlisten_port: 19787\n"), 0o600)
	if err != nil {
		t.Fatalf("write settings: %v", err)
	}

	code := cli.Run([]string{"enable", "--config", configPath, "--settings", claudePath})
	if code != 0 {
		t.Fatalf("enable exit code %d, want 0", code)
	}

	written, err := os.ReadFile(claudePath)
	if err != nil {
		t.Fatalf("read claude settings: %v", err)
	}

	if !strings.Contains(string(written), "127.0.0.1:19787") {
		t.Fatalf("claude settings %q do not hold the listener port", written)
	}

	code = cli.Run([]string{"disable", "--config", configPath, "--settings", claudePath})
	if code != 0 {
		t.Fatalf("disable exit code %d, want 0", code)
	}

	written, err = os.ReadFile(claudePath)
	if err != nil {
		t.Fatalf("read claude settings: %v", err)
	}

	if strings.Contains(string(written), "19787") {
		t.Fatalf("claude settings %q still hold the proxy", written)
	}
}

// TestLogsRejectsNegativeLines: отрицательное число строк — негодный вызов, а не молчаливое
// «ничего не показывать».
func TestLogsRejectsNegativeLines(t *testing.T) {
	t.Parallel()

	path := filepath.Join(t.TempDir(), "ipguard.yaml")

	err := os.WriteFile(path, []byte("expected_ip: 203.0.113.7\nlog_path: proxy.log\n"), 0o600)
	if err != nil {
		t.Fatalf("write settings: %v", err)
	}

	code := cli.Run([]string{"logs", "--config", path, "-n", "-1"})
	if code != cli.ExitUsage {
		t.Fatalf("exit code %d on negative lines, want %d", code, cli.ExitUsage)
	}
}

// TestLogsRejectsMissingLogDirectory: каталога журнала нет — отказ с причиной, а не ожидание
// файла, который негде создать.
func TestLogsRejectsMissingLogDirectory(t *testing.T) {
	t.Parallel()

	directory := t.TempDir()
	path := filepath.Join(directory, "ipguard.yaml")
	logPath := filepath.Join(directory, "absent", "proxy.log")

	err := os.WriteFile(path, []byte("expected_ip: 203.0.113.7\nlog_path: "+logPath+"\n"), 0o600)
	if err != nil {
		t.Fatalf("write settings: %v", err)
	}

	code := cli.Run([]string{"logs", "--config", path, "-n", "0"})
	if code != cli.ExitFailure {
		t.Fatalf("exit code %d without a log directory, want %d", code, cli.ExitFailure)
	}
}

// TestStatusFailsWithoutService: сервис не поднят — отказ с причиной, а не тишина.
func TestStatusFailsWithoutService(t *testing.T) {
	t.Parallel()

	path := filepath.Join(t.TempDir(), "ipguard.yaml")

	err := os.WriteFile(path, []byte("expected_ip: 203.0.113.7\nsecret: cli-secret\nlisten_port: 19788\n"), 0o600)
	if err != nil {
		t.Fatalf("write settings: %v", err)
	}

	code := cli.Run([]string{"status", "--config", path})
	if code != cli.ExitFailure {
		t.Fatalf("exit code %d without a service, want %d", code, cli.ExitFailure)
	}
}
