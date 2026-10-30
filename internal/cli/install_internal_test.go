package cli

import (
	"errors"
	"path/filepath"
	"testing"

	"github.com/spf13/viper"
)

// TestRequireDefaultConfigRefusesForeignFile: служба читает файл настроек из каталога
// установки, и установка по чужому файлу развела бы файл службы и файл команды.
//
// Проверка зовётся напрямую, а не через `cli.Run([]string{"install", …})`: на том пути между
// тестом и настоящей установкой на машину прогоняющего стоит ровно эта проверка — сломайся
// она, `go test ./...` положил бы бинарник в `~/.local/bin`, переписал автозапуск и дёрнул
// `launchctl`. Адреса установки и команды ОС тесты подменяют через `install.Options`.
func TestRequireDefaultConfigRefusesForeignFile(t *testing.T) {
	t.Parallel()

	reader := viper.New()
	reader.Set("config", filepath.Join(t.TempDir(), "ipguard.yaml"))

	err := requireDefaultConfig(reader)

	var coded exitError
	if !errors.As(err, &coded) || coded.code != ExitUsage {
		t.Fatalf("requireDefaultConfig gave %v, want exit code %d", err, ExitUsage)
	}

	err = requireDefaultConfig(viper.New())
	if err != nil {
		t.Fatalf("requireDefaultConfig without --config gave %v", err)
	}
}
