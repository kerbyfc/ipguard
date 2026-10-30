package cli

import (
	"fmt"
	"io"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/spf13/cobra"
	"github.com/spf13/viper"

	"github.com/kerbyfc/ipguard/internal/config"
	"github.com/kerbyfc/ipguard/internal/guard"
	"github.com/kerbyfc/ipguard/internal/proxy"
	"github.com/kerbyfc/ipguard/internal/seen"
)

// newServe — команда «поднять сервис».
func newServe(reader *viper.Viper) *cobra.Command {
	//nolint:exhaustruct // заданы имя, описание и обработчик, остальное — cobra
	command := &cobra.Command{
		Use:   "serve",
		Short: "Run the guard proxy on loopback",
		Args:  cobra.NoArgs,
		RunE: func(command *cobra.Command, _ []string) error {
			service, err := command.Flags().GetBool("service")
			if err != nil {
				return exitError{code: ExitUsage, message: err.Error()}
			}

			return serve(reader, service)
		},
	}

	command.Flags().Bool(
		"service", false,
		"start from the autostart unit: lines go only to the rotated journal, not mirrored to stderr",
	)

	return command
}

// serve поднимает прокси и держит его до сигнала остановки. service — запуск из записи
// автозапуска: признак ставит сама запись, а не угадывание по tty.
func serve(reader *viper.Viper, service bool) error {
	if service {
		hideServiceWindow()
	}

	settings, err := loadSettings(reader)
	if err != nil {
		return err
	}

	err = settings.RequireSecret()
	if err != nil {
		return exitError{code: ExitUsage, message: err.Error()}
	}

	journal, err := openJournal(settings, service)
	if err != nil {
		return err
	}

	defer func() { _ = journal.Close() }()

	table, err := openSeen(settings, journal.Printf)
	if err != nil {
		return err
	}

	// Сброс при остановке обязателен: между сроками записи накопленное живёт в памяти.
	defer closeSeen(table, journal.Printf)

	checker, err := newChecker(settings, journal.Printf)
	if err != nil {
		return exitError{code: ExitUsage, message: err.Error()}
	}

	defer checker.Stop()

	server, err := newServer(settings, checker, journal, table)
	if err != nil {
		return err
	}

	// Одна строка о границе: по журналу видно, какая настройка подхватилась. Считается после
	// прокси: он чистит таблицу от хостов, ставших исключениями, и до чистки число врало бы.
	logGuardSummary(journal.Printf, len(settings.UnguardedHosts), len(table.Entries()))

	stopOnSignal(server, checker, journal)

	err = server.Serve()
	if err != nil {
		return exitError{code: ExitFailure, message: err.Error()}
	}

	return nil
}

// newServer собирает прокси по настройкам.
func newServer(
	settings config.Settings, checker proxy.Verdicter, journal *proxy.Journal, table *seen.Store,
) (*proxy.Server, error) {
	server, err := proxy.New(proxy.Config{
		Addr:           settings.ListenAddr(),
		Secret:         settings.Secret,
		UpstreamProxy:  settings.UpstreamProxy,
		ExpectedIP:     settings.ExpectedIP,
		CheckURL:       settings.CheckURL,
		UnguardedHosts: settings.UnguardedHosts,
		Budget:         settings.Budget,
		Checker:        checker,
		Journal:        journal,
		Seen:           table,
	})
	if err != nil {
		return nil, exitError{code: ExitFailure, message: err.Error()}
	}

	return server, nil
}

// stopOnSignal останавливает прокси по сигналу: причина идёт строкой журнала, иначе выход
// не отличить от другого.
func stopOnSignal(server *proxy.Server, checker *guard.Checker, journal *proxy.Journal) {
	stop := make(chan os.Signal, 1)
	signal.Notify(stop, syscall.SIGINT, syscall.SIGTERM)

	go func() {
		received := <-stop

		journal.Printf("ipguard proxy stopping: signal %s", received)
		checker.Stop()

		_ = server.Close()
	}()
}

// logGuardSummary пишет одну строку о границе охраны: вердикта ждёт любой хост, кроме
// исключений, и столько хостов уже накоплено. Списки в журнал не переливаются.
func logGuardSummary(logf func(format string, args ...any), patterns, recorded int) {
	logf("guard: every host waits for a verdict except %d unguarded patterns; %d hosts recorded", patterns, recorded)
}

// openSeen открывает таблицу защищаемых хостов: недоступный каталог или битый файл —
// отказ с причиной, а не запуск без накопленного.
func openSeen(settings config.Settings, logf func(format string, args ...any)) (*seen.Store, error) {
	table, err := seen.Open(seen.Config{
		Path:  settings.SeenHostsPath,
		Limit: seen.DefaultLimit,
		Flush: seen.DefaultFlush,
		Now:   time.Now,
		Logf:  logf,
	})
	if err != nil {
		return nil, exitError{code: ExitFailure, message: err.Error()}
	}

	return table, nil
}

// closeSeen сбрасывает таблицу на диск при остановке; отказ записи идёт строкой журнала.
func closeSeen(table *seen.Store, logf func(format string, args ...any)) {
	err := table.Close()
	if err != nil {
		logf("seen hosts close failed: %v", err)
	}
}

// openJournal открывает журнал по настройкам. Под службой зеркала нет: её stdout и stderr
// уходят в файл, который не ротирует никто, и дублирование строк журнала растило бы его без
// предела. Запуск руками stderr сохраняет — причина видна в терминале.
func openJournal(settings config.Settings, service bool) (*proxy.Journal, error) {
	var mirror io.Writer
	if !service {
		mirror = os.Stderr
	}

	journal, err := proxy.OpenJournal(settings.LogPath, settings.LogMaxBytes, settings.LogKeep, mirror)
	if err != nil {
		return nil, exitError{code: ExitFailure, message: err.Error()}
	}

	return journal, nil
}

// newChecker собирает проверку IP по настройкам.
func newChecker(settings config.Settings, logf func(format string, args ...any)) (*guard.Checker, error) {
	checker, err := guard.NewChecker(guard.Config{
		ExpectedIP:     settings.ExpectedIP,
		CheckURL:       settings.CheckURL,
		AttemptTimeout: settings.AttemptTimeout,
		RetryDelays:    settings.RetryDelays,
		Budget:         settings.Budget,
		UpstreamProxy:  settings.UpstreamProxy,
		Clock:          guard.RealClock(),
		Fetch:          guard.FetchIP,
		Logf:           logf,
	})
	if err != nil {
		return nil, fmt.Errorf("ipguard: %w", err)
	}

	return checker, nil
}
