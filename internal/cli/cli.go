// Package cli — команды `ipguard` на cobra; файл настроек читает viper (`--config`,
// окружение IPGUARD_CONFIG, иначе файл в каталоге установки).
package cli

import (
	"errors"
	"fmt"
	"os"

	"github.com/spf13/cobra"
	"github.com/spf13/viper"

	"github.com/kerbyfc/ipguard/internal/config"
)

const (
	// ExitUsage — негодный вызов или негодные настройки.
	ExitUsage = 2
	// ExitBlocked — разовая проверка дала отказ.
	ExitBlocked = 3
	// ExitFailure — сервис не поднялся, упал или не ответил на пробу установки.
	ExitFailure = 1

	// Version — версия сторожа.
	Version = "0.1.0"

	configEnv = "IPGUARD_CONFIG"
)

// exitError несёт код возврата команды.
type exitError struct {
	code    int
	message string
}

func (err exitError) Error() string {
	return err.message
}

// Run выполняет команду и возвращает код возврата процесса.
func Run(args []string) int {
	root := newRoot()
	root.SetArgs(args)

	err := root.Execute()
	if err == nil {
		return 0
	}

	var coded exitError
	if errors.As(err, &coded) {
		if coded.message != "" {
			fmt.Fprintln(os.Stderr, "ipguard: "+coded.message)
		}

		return coded.code
	}

	fmt.Fprintln(os.Stderr, "ipguard: "+err.Error())

	return ExitUsage
}

// newRoot собирает дерево команд.
func newRoot() *cobra.Command {
	reader := viper.New()

	//nolint:exhaustruct // заданы имя, описание и поведение ошибок, остальное — cobra
	root := &cobra.Command{
		Use:           "ipguard",
		Short:         "Claude access guard: a local proxy that lets traffic through only on the expected external IP",
		SilenceUsage:  true,
		SilenceErrors: true,
	}

	root.PersistentFlags().String(
		"config", "", "settings file ("+configEnv+"; default "+config.DefaultPath()+")",
	)
	_ = reader.BindPFlag("config", root.PersistentFlags().Lookup("config"))
	_ = reader.BindEnv("config", configEnv)

	root.AddCommand(
		newServe(reader),
		newCheck(reader),
		newLogs(reader),
		newStatus(reader),
		newWhitelist(reader, defaultTarget),
		newInstall(reader),
		newUninstall(reader),
		newEnable(reader),
		newDisable(reader),
		newVersion(),
	)

	return root
}

// settingsPath — файл настроек по `--config`, окружению или каталогу установки.
func settingsPath(reader *viper.Viper) string {
	path := reader.GetString("config")
	if path == "" {
		return config.DefaultPath()
	}

	return path
}

// loadSettings читает настройки по `--config`: битый файл или поле вне допустимого — отказ
// с кодом ExitUsage, файла нет — встроенные значения.
func loadSettings(reader *viper.Viper) (config.Settings, error) {
	settings, err := config.Load(settingsPath(reader))
	if err != nil {
		return settings, exitError{code: ExitUsage, message: err.Error()}
	}

	return settings, nil
}
