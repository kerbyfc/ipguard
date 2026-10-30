package install

import (
	"encoding/json"
	"fmt"
	"io"
	"net/url"
	"os"
	"path/filepath"

	"github.com/kerbyfc/ipguard/internal/config"
)

const (
	// ClaudeDirName — каталог настроек Claude Code в домашнем каталоге.
	ClaudeDirName = ".claude"
	// ClaudeSettingsName — файл настроек Claude Code.
	ClaudeSettingsName = "settings.json"
	// BackupSuffix — копия настроек Claude Code перед правкой; переписывается каждый раз.
	BackupSuffix = ".ipguard-backup"

	envKey        = "env"
	httpsProxyKey = "HTTPS_PROXY"
	httpProxyKey  = "HTTP_PROXY"
	proxyUser     = "claude"

	settingsMode os.FileMode = 0o600
)

// lowerKeys — строчные имена тех же переменных. Claude Code берёт первую заданную и считает
// строчные приоритетнее, поэтому при их наличии сторож отказывается править файл: иначе
// прокси прописан, а трафик идёт по чужой настройке.
var lowerKeys = []string{"https_proxy", "http_proxy"}

// ClaudeSettingsPath — файл настроек Claude Code этой машины.
func ClaudeSettingsPath() (string, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return "", fmt.Errorf("%w: home directory is unknown: %w", ErrInstall, err)
	}

	return filepath.Join(home, ClaudeDirName, ClaudeSettingsName), nil
}

// ProxyURL — значение переменных прокси по нынешним настройкам сторожа: адрес и порт
// слушателя и его секрет.
func ProxyURL(settings config.Settings) string {
	return "http://" + proxyUser + ":" + settings.Secret + "@" + settings.ListenAddr()
}

// EnableClaude прописывает прокси сторожа в блок `env` настроек Claude Code. Значения уже те
// же — файл не трогается. Переменные читаются один раз при старте, поэтому claude после
// правки надо перезапустить.
func EnableClaude(settings config.Settings, path string, out io.Writer) error {
	report := reporter{out: out}
	report.line("ipguard enable (+ done, = already done)")

	document, err := readSettings(path)
	if err != nil {
		return err
	}

	block, err := envBlock(document, path)
	if err != nil {
		return err
	}

	value := ProxyURL(settings)
	if block[httpsProxyKey] == value && block[httpProxyKey] == value {
		report.step("claude", Change{Done: false, Note: "the proxy is already set, " + path})
		report.ended(settings, path)

		return nil
	}

	block[httpsProxyKey] = value
	block[httpProxyKey] = value
	document[envKey] = block

	err = saveSettings(path, document, report)
	if err != nil {
		return err
	}

	report.step("claude", Change{Done: true, Note: httpsProxyKey + " and " + httpProxyKey + " written, " + path})
	report.ended(settings, path)

	return nil
}

// DisableClaude убирает из настроек Claude Code переменные прокси, указывающие на этот
// сторож: адрес и порт нынешних настроек и пользователь `claude`. Чужое значение остаётся, и
// отчёт его называет: `disable` владелец зовёт как «вернуть как было», а не как «снести
// прокси». Секрет не сверяется — он мог смениться после `enable`.
func DisableClaude(settings config.Settings, path string, out io.Writer) error {
	report := reporter{out: out}
	report.line("ipguard disable (+ done, = already done)")

	document, err := readSettings(path)
	if err != nil {
		return err
	}

	block, err := envBlock(document, path)
	if err != nil {
		return err
	}

	dropped := dropProxyKeys(block, settings, report)
	if !dropped {
		report.step("claude", Change{Done: false, Note: "the guard proxy is not set, " + path})

		return nil
	}

	if len(block) == 0 {
		delete(document, envKey)
	} else {
		document[envKey] = block
	}

	err = saveSettings(path, document, report)
	if err != nil {
		return err
	}

	report.step("claude", Change{Done: true, Note: "the guard proxy variables are removed, " + path})
	report.line("")
	report.line("restart claude: environment variables are read once at startup")

	return nil
}

// dropProxyKeys убирает из блока `env` только значения этого сторожа и отвечает, убрал ли
// хоть одно. Чужое значение остаётся строкой отчёта: о потере чужого прокси владелец узнавал
// бы задним числом по копии файла.
func dropProxyKeys(block map[string]any, settings config.Settings, report reporter) bool {
	dropped := false

	for _, key := range []string{httpsProxyKey, httpProxyKey} {
		value, taken := block[key]
		if !taken {
			continue
		}

		text, isText := value.(string)
		if isText && isOwnProxy(text, settings) {
			delete(block, key)

			dropped = true

			continue
		}

		report.step(key, Change{Done: false, Note: "kept, " + describeForeign(value)})
	}

	return dropped
}

// isOwnProxy — указывает ли значение переменной на этого сторожа: схема, пользователь, адрес
// и порт нынешних настроек. Секрет не сверяется: он мог смениться после `enable`.
func isOwnProxy(value string, settings config.Settings) bool {
	parsed, err := url.Parse(value)
	if err != nil {
		return false
	}

	user := parsed.User
	if user == nil {
		return false
	}

	return parsed.Scheme == "http" && user.Username() == proxyUser && parsed.Host == settings.ListenAddr()
}

// describeForeign — чужое значение для отчёта без его секрета: у прокси-ссылки называется
// только адрес, остальное — тип значения.
func describeForeign(value any) string {
	text, isText := value.(string)
	if !isText {
		return fmt.Sprintf("the value is not a string (%T)", value)
	}

	parsed, err := url.Parse(text)
	if err != nil || parsed.Host == "" {
		return "the value does not parse as a proxy address"
	}

	return "foreign proxy " + parsed.Scheme + "://" + parsed.Host
}

// readSettings читает настройки Claude Code; файла нет — пустой документ, он будет создан.
func readSettings(path string) (map[string]any, error) {
	content, err := os.ReadFile(path)

	switch {
	case err == nil:
	case os.IsNotExist(err):
		return map[string]any{}, nil
	default:
		return nil, fmt.Errorf("%w: %s: %w", ErrInstall, path, err)
	}

	document := map[string]any{}

	err = json.Unmarshal(content, &document)
	if err != nil {
		return nil, fmt.Errorf("%w: %s is not readable JSON: %w", ErrInstall, path, err)
	}

	return document, nil
}

// envBlock достаёт блок `env` настроек. Блок не словарь — отказ: править такой файл сторож
// не вправе. Строчные имена тех же переменных — тоже отказ: они приоритетнее.
func envBlock(document map[string]any, path string) (map[string]any, error) {
	raw, ok := document[envKey]
	if !ok {
		return map[string]any{}, nil
	}

	block, ok := raw.(map[string]any)
	if !ok {
		return nil, fmt.Errorf("%w: %s: key %q is not an object", ErrInstall, path, envKey)
	}

	for _, key := range lowerKeys {
		_, taken := block[key]
		if taken {
			return nil, fmt.Errorf(
				"%w: %s: env has %q, and lowercase wins over %s: remove it yourself",
				ErrInstall, path, key, httpsProxyKey,
			)
		}
	}

	return block, nil
}

// saveSettings пишет настройки Claude Code, оставив рядом копию прежнего файла. Порядок
// ключей при перезаписи задаёт сериализация JSON, а не прежний файл, — поэтому копия.
func saveSettings(path string, document map[string]any, report reporter) error {
	content, err := json.MarshalIndent(document, "", "  ")
	if err != nil {
		return fmt.Errorf("%w: %s: %w", ErrInstall, path, err)
	}

	content = append(content, '\n')

	previous, err := os.ReadFile(path)

	switch {
	case err == nil:
		backupErr := writeFile(path+BackupSuffix, previous, settingsMode)
		if backupErr != nil {
			return backupErr
		}

		report.step("backup", Change{Done: true, Note: "the previous file, " + path + BackupSuffix})
	case os.IsNotExist(err):
		report.step("file", Change{Done: true, Note: "created, " + path})
	default:
		return fmt.Errorf("%w: %s: %w", ErrInstall, path, err)
	}

	return writeFile(path, content, settingsMode)
}
