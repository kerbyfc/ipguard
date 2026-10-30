package cli

import (
	"fmt"
	"os"
	"os/signal"
	"syscall"

	"github.com/spf13/cobra"
	"github.com/spf13/viper"

	"github.com/kerbyfc/ipguard/internal/logtail"
)

// newLogs — команда «хвост журнала»: последние строки, затем дописываемые до Ctrl+C.
func newLogs(reader *viper.Viper) *cobra.Command {
	//nolint:exhaustruct // заданы имя, описание и обработчик, остальное — cobra
	command := &cobra.Command{
		Use:   "logs",
		Short: "Follow the guard journal: the last lines, then new ones until Ctrl+C",
		Args:  cobra.NoArgs,
		RunE: func(command *cobra.Command, _ []string) error {
			lines, err := command.Flags().GetInt("lines")
			if err != nil {
				return exitError{code: ExitUsage, message: err.Error()}
			}

			return showLogs(command, reader, lines)
		},
	}

	command.Flags().IntP(
		"lines", "n", logtail.DefaultLines,
		"how many last lines to print first (0 — only new ones)",
	)

	return command
}

// showLogs печатает хвост журнала до сигнала остановки. Секрет и служба команде не нужны:
// она читает файл из настроек и в сеть не ходит.
func showLogs(command *cobra.Command, reader *viper.Viper, lines int) error {
	if lines < 0 {
		return exitError{
			code:    ExitUsage,
			message: fmt.Sprintf("--lines must not be negative, got %d", lines),
		}
	}

	settings, err := loadSettings(reader)
	if err != nil {
		return err
	}

	ctx, stop := signal.NotifyContext(command.Context(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	err = logtail.Follow(ctx, logtail.Config{
		Path:  settings.LogPath,
		Lines: lines,
		Out:   command.OutOrStdout(),
		Poll:  logtail.DefaultPoll,
	})
	if err != nil {
		return exitError{code: ExitFailure, message: err.Error()}
	}

	return nil
}
