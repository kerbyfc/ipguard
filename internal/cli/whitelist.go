package cli

import (
	"fmt"
	"io"
	"path/filepath"
	"runtime"
	"slices"
	"strings"

	"github.com/spf13/cobra"
	"github.com/spf13/viper"

	"github.com/kerbyfc/ipguard/internal/config"
	"github.com/kerbyfc/ipguard/internal/hosts"
	"github.com/kerbyfc/ipguard/internal/install"
)

// guardTarget — автозапуск этой машины и файл настроек, который читает служба.
type guardTarget struct {
	// Service — автозапуск: им правка вступает в силу.
	Service install.Service
	// Config — файл настроек службы. Правка другого файла службе не видна, и перезапуск по
	// ней был бы ложью, а не делом.
	Config string
}

// targetSource — цель правки. Поле команды, а не прямой вызов: тесты подставляют свою и не
// трогают launchd и планировщик настоящей машины.
type targetSource func() (guardTarget, error)

// newWhitelist — команда «белый список»: без аргументов печатает нынешний, с аргументами
// дописывает шаблоны в настройки и перезапускает службу.
func newWhitelist(reader *viper.Viper, source targetSource) *cobra.Command {
	//nolint:exhaustruct // заданы имя, описание и обработчик, остальное — cobra
	return &cobra.Command{
		Use:   "whitelist [pattern...]",
		Short: "Hosts out of guard: without arguments prints the list, with arguments adds patterns",
		Args:  cobra.ArbitraryArgs,
		RunE: func(command *cobra.Command, args []string) error {
			return whitelist(command, reader, args, source)
		},
	}
}

// whitelist печатает или правит белый список. Все аргументы проверяются теми же правилами,
// что и сверка хостов, до первой правки: среди годных негодный — отказ, а не запись по части
// шаблонов.
func whitelist(command *cobra.Command, reader *viper.Viper, args []string, source targetSource) error {
	settings, err := loadSettings(reader)
	if err != nil {
		return err
	}

	out := command.OutOrStdout()

	if len(args) == 0 {
		printPatterns(out, settings.UnguardedHosts)

		return nil
	}

	known, err := hosts.Canonicalize(settings.UnguardedHosts)
	if err != nil {
		return exitError{code: ExitUsage, message: "unguarded_hosts: " + err.Error()}
	}

	requested, err := canonicalArgs(args)
	if err != nil {
		return exitError{code: ExitUsage, message: err.Error()}
	}

	added := make([]string, 0, len(requested))
	for _, pattern := range requested {
		if slices.Contains(known, pattern) {
			_, _ = fmt.Fprintln(out, "= already set: "+pattern)

			continue
		}

		added = append(added, pattern)
	}

	if len(added) == 0 {
		return nil
	}

	path := settingsPath(reader)

	change, err := install.AddUnguardedHost(path, added)
	if err != nil {
		return exitError{code: ExitFailure, message: err.Error()}
	}

	for _, note := range strings.Split(change.Note, "\n") {
		_, _ = fmt.Fprintln(out, "+ "+note)
	}

	return applyToService(out, path, source)
}

// canonicalArgs приводит аргументы к виду сверки и схлопывает повторы внутри команды: повтор
// шаблона — не два пункта в файле, а тот же.
func canonicalArgs(args []string) ([]string, error) {
	patterns := make([]string, 0, len(args))

	for _, arg := range args {
		pattern, err := hosts.Canonical(arg)
		if err != nil {
			return nil, err
		}

		if slices.Contains(patterns, pattern) {
			continue
		}

		patterns = append(patterns, pattern)
	}

	return patterns, nil
}

// applyToService перезапускает службу, чтобы правка подхватилась без ручных команд. Правка
// чужого файла (`--config`) службе не видна: она читает файл из каталога установки, и
// перезапуск по чужой правке сказал бы «в силе» о том, чего служба не увидит.
func applyToService(out io.Writer, path string, source targetSource) error {
	target, err := source()
	if err != nil {
		return exitError{code: ExitFailure, message: err.Error()}
	}

	same, err := samePath(path, target.Config)
	if err != nil {
		return exitError{code: ExitUsage, message: err.Error()}
	}

	if !same {
		_, _ = fmt.Fprintln(out, "! the service reads "+target.Config+": this edit will not take effect")

		return nil
	}

	// Автозапуска на этой ОС нет: правка файла — всё, что команда может сделать, а службу
	// владелец держит и перезапускает сам. Молчать об этом нельзя: список без перезапуска
	// ещё не в силе, и отчёт обязан назвать, чего не хватает.
	if target.Service == nil {
		_, _ = fmt.Fprintln(
			out,
			"! no autostart on this platform: restart the service yourself for the list to take effect",
		)

		return nil
	}

	return restartService(out, target.Service)
}

// samePath — один ли это файл: пути сравниваются после раскрытия `~` и приведения к
// абсолютным, иначе `--config ./ipguard.yaml` в каталоге установки считался бы чужим.
func samePath(left, right string) (bool, error) {
	expanded, err := config.ExpandHome(left)
	if err != nil {
		return false, fmt.Errorf("ipguard: %w", err)
	}

	absLeft, err := filepath.Abs(expanded)
	if err != nil {
		return false, fmt.Errorf("ipguard: %s: %w", left, err)
	}

	absRight, err := filepath.Abs(right)
	if err != nil {
		return false, fmt.Errorf("ipguard: %s: %w", right, err)
	}

	return absLeft == absRight, nil
}

// restartService перезапускает службу. Службы нет — об этом говорится прямо: тихий успех
// выдал бы правку за вступившую в силу.
func restartService(out io.Writer, service install.Service) error {
	installed, err := service.Installed()
	if err != nil {
		return exitError{code: ExitFailure, message: err.Error()}
	}

	if !installed {
		_, _ = fmt.Fprintln(out, "! there is no autostart: the list takes effect after `ipguard install`")

		return nil
	}

	err = service.Restart()
	if err != nil {
		return exitError{code: ExitFailure, message: err.Error()}
	}

	_, _ = fmt.Fprintln(out, "+ the service is restarted: the list is in force")

	return nil
}

// printPatterns печатает белый список в порядке перевёрнутых меток имени.
func printPatterns(out io.Writer, patterns []string) {
	if len(patterns) == 0 {
		_, _ = fmt.Fprintln(
			out,
			"the whitelist is empty: every host waits for a verdict except the check host and local addresses",
		)

		return
	}

	_, _ = fmt.Fprintf(out, "exceptions (%d):\n", len(patterns))

	for _, pattern := range sortedPatterns(patterns) {
		_, _ = fmt.Fprintln(out, "  "+pattern)
	}
}

// sortedPatterns — копия списка в порядке перевёрнутых меток.
func sortedPatterns(patterns []string) []string {
	sorted := make([]string, len(patterns))
	copy(sorted, patterns)

	slices.SortFunc(sorted, hosts.Compare)

	return sorted
}

// defaultTarget — служба этой машины и файл настроек, который она читает.
func defaultTarget() (guardTarget, error) {
	return targetFor(runtime.GOOS)
}

// targetFor — цель правки для ОС goos. ОС без автозапуска получает цель без службы и путь к
// файлу службы по умолчанию: адреса установки для неё не считаются, `install.DefaultPaths`
// на такой ОС отказывает, а команда белого списка обязана работать и там.
func targetFor(goos string) (guardTarget, error) {
	empty := guardTarget{Service: nil, Config: ""}

	if goos != install.GOOSDarwin && goos != install.GOOSWindows {
		return guardTarget{Service: nil, Config: config.DefaultPath()}, nil
	}

	paths, err := install.DefaultPaths(goos)
	if err != nil {
		return empty, fmt.Errorf("ipguard: %w", err)
	}

	service, err := install.PickService(goos, paths, install.ExecRunner)
	if err != nil {
		return empty, fmt.Errorf("ipguard: %w", err)
	}

	return guardTarget{Service: service, Config: paths.Config}, nil
}
