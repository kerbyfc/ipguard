package cli

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"
	"github.com/spf13/viper"

	"github.com/kerbyfc/ipguard/internal/proxy"
)

// newCheck — разовая проверка для диагностики: тем же кодом, что и прокси, но без слушателя.
func newCheck(reader *viper.Viper) *cobra.Command {
	//nolint:exhaustruct // заданы имя, описание и обработчик, остальное — cobra
	command := &cobra.Command{
		Use:   "check",
		Short: "One-off external IP check: exit code 0 on a match, 3 on a block",
		Args:  cobra.NoArgs,
		RunE: func(command *cobra.Command, _ []string) error {
			return check(command, reader)
		},
	}

	return command
}

// check печатает вердикт и отдаёт код: 0 — пропуск, ExitBlocked — отказ.
func check(command *cobra.Command, reader *viper.Viper) error {
	settings, err := loadSettings(reader)
	if err != nil {
		return err
	}

	checker, err := newChecker(settings, proxy.NewJournal(os.Stderr).Printf)
	if err != nil {
		return exitError{code: ExitUsage, message: err.Error()}
	}

	defer checker.Stop()

	verdict, err := checker.Verdict(command.Context())
	if err != nil {
		return exitError{code: ExitFailure, message: err.Error()}
	}

	if verdict.Allowed() {
		_, _ = fmt.Fprintf(
			command.OutOrStdout(),
			"ipguard: external IP %s matches, checked at %s\n",
			verdict.IP, verdict.At.Format("15:04:05"),
		)

		return nil
	}

	return exitError{
		code:    ExitBlocked,
		message: verdict.Message(settings.ExpectedIP, settings.CheckURL, settings.Budget),
	}
}

// newVersion — команда «версия».
func newVersion() *cobra.Command {
	//nolint:exhaustruct // заданы имя, описание и обработчик, остальное — cobra
	return &cobra.Command{
		Use:   "version",
		Short: "Print the guard version",
		Args:  cobra.NoArgs,
		RunE: func(command *cobra.Command, _ []string) error {
			_, _ = fmt.Fprintln(command.OutOrStdout(), "ipguard "+Version)

			return nil
		},
	}
}
