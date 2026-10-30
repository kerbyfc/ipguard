package cli

import (
	"runtime"

	"github.com/spf13/cobra"
	"github.com/spf13/viper"

	"github.com/kerbyfc/ipguard/internal/config"
	"github.com/kerbyfc/ipguard/internal/install"
)

// newInstall — команда «поставить сторожа на эту машину».
func newInstall(reader *viper.Viper) *cobra.Command {
	//nolint:exhaustruct // заданы имя, описание и обработчик, остальное — cobra
	command := &cobra.Command{
		Use:   "install",
		Short: "Install the guard: binary, settings, OS autostart and a live service probe",
		Args:  cobra.NoArgs,
		RunE: func(command *cobra.Command, _ []string) error {
			return runInstall(command, reader)
		},
	}

	command.Flags().String("expected-ip", "", "expected external IP for a new settings file")
	command.Flags().Bool("yes", false, "accept the detected external IP without asking")

	return command
}

// newUninstall — команда «снять автозапуск».
func newUninstall(reader *viper.Viper) *cobra.Command {
	//nolint:exhaustruct // заданы имя, описание и обработчик, остальное — cobra
	return &cobra.Command{
		Use:   "uninstall",
		Short: "Remove the autostart unit and stop the service; settings, journal and binary stay",
		Args:  cobra.NoArgs,
		RunE: func(command *cobra.Command, _ []string) error {
			return runUninstall(command, reader)
		},
	}
}

// newEnable — команда «прописать прокси сторожа в настройки Claude Code».
func newEnable(reader *viper.Viper) *cobra.Command {
	//nolint:exhaustruct // заданы имя, описание и обработчик, остальное — cobra
	command := &cobra.Command{
		Use:   "enable",
		Short: "Write the guard proxy into the env block of Claude Code settings from the current settings",
		Args:  cobra.NoArgs,
		RunE: func(command *cobra.Command, _ []string) error {
			return runEnable(command, reader)
		},
	}

	command.Flags().String("settings", "", "Claude Code settings file (default ~/.claude/settings.json)")

	return command
}

// newDisable — команда «убрать прокси сторожа из настроек Claude Code».
func newDisable(reader *viper.Viper) *cobra.Command {
	//nolint:exhaustruct // заданы имя, описание и обработчик, остальное — cobra
	command := &cobra.Command{
		Use:   "disable",
		Short: "Remove the guard proxy variables from Claude Code settings",
		Args:  cobra.NoArgs,
		RunE: func(command *cobra.Command, _ []string) error {
			return runDisable(command, reader)
		},
	}

	command.Flags().String("settings", "", "Claude Code settings file (default ~/.claude/settings.json)")

	return command
}

// runInstall ставит сторожа. `--config` установке не передаётся: она работает с каталогом
// установки, и подмена пути настроек развела бы файл службы и файл команды.
func runInstall(command *cobra.Command, reader *viper.Viper) error {
	err := requireDefaultConfig(reader)
	if err != nil {
		return err
	}

	options, err := install.DefaultOptions(runtime.GOOS)
	if err != nil {
		return exitError{code: ExitUsage, message: err.Error()}
	}

	options.Out = command.OutOrStdout()

	options.ExpectedIP, err = command.Flags().GetString("expected-ip")
	if err != nil {
		return exitError{code: ExitUsage, message: err.Error()}
	}

	options.AssumeYes, err = command.Flags().GetBool("yes")
	if err != nil {
		return exitError{code: ExitUsage, message: err.Error()}
	}

	err = install.Install(command.Context(), options)
	if err != nil {
		return exitError{code: ExitFailure, message: err.Error()}
	}

	return nil
}

// runUninstall снимает автозапуск.
func runUninstall(command *cobra.Command, reader *viper.Viper) error {
	err := requireDefaultConfig(reader)
	if err != nil {
		return err
	}

	options, err := install.DefaultOptions(runtime.GOOS)
	if err != nil {
		return exitError{code: ExitUsage, message: err.Error()}
	}

	options.Out = command.OutOrStdout()

	err = install.Uninstall(options)
	if err != nil {
		return exitError{code: ExitFailure, message: err.Error()}
	}

	return nil
}

// runEnable прописывает прокси в настройки Claude Code.
func runEnable(command *cobra.Command, reader *viper.Viper) error {
	settings, err := loadSettings(reader)
	if err != nil {
		return err
	}

	err = settings.RequireSecret()
	if err != nil {
		return exitError{code: ExitUsage, message: err.Error()}
	}

	path, err := claudeSettingsPath(command)
	if err != nil {
		return err
	}

	err = install.EnableClaude(settings, path, command.OutOrStdout())
	if err != nil {
		return exitError{code: ExitFailure, message: err.Error()}
	}

	return nil
}

// runDisable убирает прокси из настроек Claude Code. Настройки сторожа нужны и здесь: по
// адресу и порту слушателя команда отличает своё значение переменной от чужого. Секрета
// `disable` не требует — он мог смениться после `enable`.
func runDisable(command *cobra.Command, reader *viper.Viper) error {
	settings, err := loadSettings(reader)
	if err != nil {
		return err
	}

	path, err := claudeSettingsPath(command)
	if err != nil {
		return err
	}

	err = install.DisableClaude(settings, path, command.OutOrStdout())
	if err != nil {
		return exitError{code: ExitFailure, message: err.Error()}
	}

	return nil
}

// claudeSettingsPath — файл настроек Claude Code из флага или домашнего каталога.
func claudeSettingsPath(command *cobra.Command) (string, error) {
	path, err := command.Flags().GetString("settings")
	if err != nil {
		return "", exitError{code: ExitUsage, message: err.Error()}
	}

	if path != "" {
		expanded, expandErr := config.ExpandHome(path)
		if expandErr != nil {
			return "", exitError{code: ExitUsage, message: expandErr.Error()}
		}

		return expanded, nil
	}

	path, err = install.ClaudeSettingsPath()
	if err != nil {
		return "", exitError{code: ExitUsage, message: err.Error()}
	}

	return path, nil
}

// requireDefaultConfig отказывает установке с чужим файлом настроек: служба читает файл из
// каталога установки, и тихо работать по другому файлу она не должна.
func requireDefaultConfig(reader *viper.Viper) error {
	if reader.GetString("config") == "" {
		return nil
	}

	return exitError{
		code:    ExitUsage,
		message: "install and uninstall work with the install directory only: --config is not supported",
	}
}
