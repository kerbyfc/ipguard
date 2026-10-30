package install_test

import (
	"bytes"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/kerbyfc/ipguard/internal/config"
	"github.com/kerbyfc/ipguard/internal/install"
)

// TestEnableWritesProxyEnv: команда прописывает прокси сторожа в блок `env` настроек Claude
// Code по нынешнему адресу и порту слушателя, а сам секрет в терминал не выводит.
func TestEnableWritesProxyEnv(t *testing.T) {
	t.Parallel()

	path := filepath.Join(t.TempDir(), ".claude", "settings.json")
	settings := claudeSettings()
	out := &bytes.Buffer{}

	err := install.EnableClaude(settings, path, out)
	if err != nil {
		t.Fatalf("enable: %v", err)
	}

	block := envOf(t, path)
	want := install.ProxyURL(settings)

	if block["HTTPS_PROXY"] != want || block["HTTP_PROXY"] != want {
		t.Fatalf("env block %v, want both proxy variables %q", block, want)
	}

	if !strings.Contains(want, settings.ListenAddr()) {
		t.Fatalf("proxy URL %q does not hold the listener address", want)
	}

	report := out.String()
	if strings.Contains(report, settings.Secret) {
		t.Fatalf("report printed the secret:\n%s", report)
	}

	if !strings.Contains(report, "restart claude") || !strings.Contains(report, path) {
		t.Fatalf("report does not say what to do next:\n%s", report)
	}
}

// TestEnableIsIdempotent: значения уже те же — файл не трогается, и копия не плодится.
func TestEnableIsIdempotent(t *testing.T) {
	t.Parallel()

	path := filepath.Join(t.TempDir(), "settings.json")
	settings := claudeSettings()

	err := install.EnableClaude(settings, path, &bytes.Buffer{})
	if err != nil {
		t.Fatalf("first enable: %v", err)
	}

	written := readTestFile(t, path)
	out := &bytes.Buffer{}

	err = install.EnableClaude(settings, path, out)
	if err != nil {
		t.Fatalf("second enable: %v", err)
	}

	if readTestFile(t, path) != written {
		t.Fatal("second enable rewrote the settings file")
	}

	if stepMark(t, out.String(), "claude") != "=" {
		t.Fatalf("second enable does not confirm the settled proxy:\n%s", out.String())
	}

	_, err = os.Stat(path + install.BackupSuffix)
	if !os.IsNotExist(err) {
		t.Fatalf("stat backup gave %v, want no backup for an unchanged file", err)
	}
}

// TestEnableKeepsOtherSettingsAndBacksUp: порядок ключей задаёт сериализация JSON, поэтому
// рядом остаётся копия прежнего файла, а чужие ключи и переменные сохраняются.
func TestEnableKeepsOtherSettingsAndBacksUp(t *testing.T) {
	t.Parallel()

	path := filepath.Join(t.TempDir(), "settings.json")
	previous := `{"env":{"FOO":"bar"},"permissions":{"allow":["Bash"]}}`
	writeTestFile(t, path, previous)

	err := install.EnableClaude(claudeSettings(), path, &bytes.Buffer{})
	if err != nil {
		t.Fatalf("enable: %v", err)
	}

	block := envOf(t, path)
	if block["FOO"] != "bar" {
		t.Fatalf("env block %v lost the other variable", block)
	}

	document := documentOf(t, path)
	if document["permissions"] == nil {
		t.Fatalf("settings %v lost the other keys", document)
	}

	if readTestFile(t, path+install.BackupSuffix) != previous {
		t.Fatal("backup does not hold the previous file")
	}
}

// TestEnableRefusesLowercaseProxy: строчные имена приоритетнее, и с ними прокси был бы
// прописан, а трафик шёл бы по чужой настройке.
func TestEnableRefusesLowercaseProxy(t *testing.T) {
	t.Parallel()

	path := filepath.Join(t.TempDir(), "settings.json")
	previous := `{"env":{"https_proxy":"http://127.0.0.1:3128"}}`
	writeTestFile(t, path, previous)

	err := install.EnableClaude(claudeSettings(), path, &bytes.Buffer{})
	if !errors.Is(err, install.ErrInstall) {
		t.Fatalf("enable gave %v, want an install error", err)
	}

	if !strings.Contains(err.Error(), "https_proxy") {
		t.Fatalf("error %q does not name the lowercase variable", err)
	}

	if readTestFile(t, path) != previous {
		t.Fatal("refused enable still rewrote the settings")
	}
}

// TestEnableRefusesBrokenFile: блок `env` не словарь или файл не JSON — правка не идёт.
func TestEnableRefusesBrokenFile(t *testing.T) {
	t.Parallel()

	cases := map[string]string{
		"env не словарь": `{"env": 5}`,
		"не JSON":        `{ this is not json`,
	}

	for name, body := range cases {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			path := filepath.Join(t.TempDir(), "settings.json")
			writeTestFile(t, path, body)

			err := install.EnableClaude(claudeSettings(), path, &bytes.Buffer{})
			if !errors.Is(err, install.ErrInstall) {
				t.Fatalf("enable gave %v, want an install error", err)
			}

			if readTestFile(t, path) != body {
				t.Fatal("refused enable still rewrote the settings")
			}
		})
	}
}

// TestDisableRemovesOnlyProxy: снятие убирает переменные прокси сторожа, оставляя остальные.
// Секрет в значении не сверяется — он мог смениться после `enable`.
func TestDisableRemovesOnlyProxy(t *testing.T) {
	t.Parallel()

	settings := claudeSettings()
	path := filepath.Join(t.TempDir(), "settings.json")
	proxy := "http://claude:another-secret@" + settings.ListenAddr()
	writeTestFile(t, path, `{"env":{"HTTPS_PROXY":"`+proxy+`","HTTP_PROXY":"`+proxy+`","FOO":"bar"}}`)

	out := &bytes.Buffer{}

	err := install.DisableClaude(settings, path, out)
	if err != nil {
		t.Fatalf("disable: %v", err)
	}

	block := envOf(t, path)
	if len(block) != 1 || block["FOO"] != "bar" {
		t.Fatalf("env block %v, want only the other variable", block)
	}

	if !strings.Contains(out.String(), "restart claude") {
		t.Fatalf("report does not say what to do next:\n%s", out.String())
	}
}

// TestDisableDropsEmptyEnv: блок `env` остался пустым — он убирается целиком, чтобы в файле
// не оставалось следов сторожа.
func TestDisableDropsEmptyEnv(t *testing.T) {
	t.Parallel()

	settings := claudeSettings()
	path := filepath.Join(t.TempDir(), "settings.json")
	writeTestFile(t, path, `{"env":{"HTTPS_PROXY":"`+install.ProxyURL(settings)+`"},"model":"opus"}`)

	err := install.DisableClaude(settings, path, &bytes.Buffer{})
	if err != nil {
		t.Fatalf("disable: %v", err)
	}

	document := documentOf(t, path)

	_, kept := document["env"]
	if kept {
		t.Fatalf("settings %v kept an empty env block", document)
	}

	if document["model"] != "opus" {
		t.Fatalf("settings %v lost the other keys", document)
	}
}

// TestDisableConfirmsCleanFile: прокси не прописан — подтверждение, а не правка и не копия.
func TestDisableConfirmsCleanFile(t *testing.T) {
	t.Parallel()

	path := filepath.Join(t.TempDir(), "settings.json")
	previous := `{"env":{"FOO":"bar"}}`
	writeTestFile(t, path, previous)

	out := &bytes.Buffer{}

	err := install.DisableClaude(claudeSettings(), path, out)
	if err != nil {
		t.Fatalf("disable: %v", err)
	}

	if readTestFile(t, path) != previous {
		t.Fatal("disable rewrote a file without the proxy")
	}

	if stepMark(t, out.String(), "claude") != "=" {
		t.Fatalf("report does not confirm the clean file:\n%s", out.String())
	}

	_, err = os.Stat(path + install.BackupSuffix)
	if !os.IsNotExist(err) {
		t.Fatalf("stat backup gave %v, want no backup for an unchanged file", err)
	}
}

// TestDisableKeepsForeignProxy: чужой прокси в блоке `env` остаётся — `disable` владелец
// зовёт как «вернуть как было», и о потере корпоративного прокси он узнавал бы задним числом
// по копии файла. Своё значение рядом при этом убирается.
func TestDisableKeepsForeignProxy(t *testing.T) {
	t.Parallel()

	settings := claudeSettings()
	path := filepath.Join(t.TempDir(), "settings.json")
	foreign := "http://corp-user:corp-secret@proxy.corp.example:3128"
	writeTestFile(
		t, path,
		`{"env":{"HTTPS_PROXY":"`+foreign+`","HTTP_PROXY":"`+install.ProxyURL(settings)+`"}}`,
	)

	out := &bytes.Buffer{}

	err := install.DisableClaude(settings, path, out)
	if err != nil {
		t.Fatalf("disable: %v", err)
	}

	block := envOf(t, path)
	if block["HTTPS_PROXY"] != foreign {
		t.Fatalf("env block %v lost the foreign proxy", block)
	}

	_, own := block["HTTP_PROXY"]
	if own {
		t.Fatalf("env block %v kept the proxy of this guard", block)
	}

	report := out.String()
	if !strings.Contains(report, "kept") || !strings.Contains(report, "proxy.corp.example:3128") {
		t.Fatalf("report does not name the kept foreign value:\n%s", report)
	}

	if strings.Contains(report, "corp-secret") {
		t.Fatalf("report printed the credentials of the foreign proxy:\n%s", report)
	}
}

// TestDisableConfirmsForeignOnlyFile: в блоке `env` только чужой прокси — файл не правится
// вовсе, и отчёт говорит, что прокси сторожа там нет.
func TestDisableConfirmsForeignOnlyFile(t *testing.T) {
	t.Parallel()

	path := filepath.Join(t.TempDir(), "settings.json")
	previous := `{"env":{"HTTPS_PROXY":"http://proxy.corp.example:3128"}}`
	writeTestFile(t, path, previous)

	out := &bytes.Buffer{}

	err := install.DisableClaude(claudeSettings(), path, out)
	if err != nil {
		t.Fatalf("disable: %v", err)
	}

	if readTestFile(t, path) != previous {
		t.Fatal("disable rewrote a file holding only a foreign proxy")
	}

	if stepMark(t, out.String(), "claude") != "=" {
		t.Fatalf("report does not confirm that the guard proxy is absent:\n%s", out.String())
	}
}

// claudeSettings — настройки сторожа с секретом и своим портом: прокси в claude прописывается
// по ним, а не по встроенному порту.
func claudeSettings() config.Settings {
	settings := config.Defaults()
	settings.Secret = "secret-of-the-listener"
	settings.ListenPort = 18787

	return settings
}

// envOf — блок `env` настроек Claude Code.
func envOf(t *testing.T, path string) map[string]any {
	t.Helper()

	block, ok := documentOf(t, path)["env"].(map[string]any)
	if !ok {
		t.Fatalf("settings %s have no env object", path)
	}

	return block
}

// documentOf — разобранные настройки Claude Code.
func documentOf(t *testing.T, path string) map[string]any {
	t.Helper()

	document := map[string]any{}

	err := json.Unmarshal([]byte(readTestFile(t, path)), &document)
	if err != nil {
		t.Fatalf("read %s as JSON: %v", path, err)
	}

	return document
}
