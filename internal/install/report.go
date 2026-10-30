package install

import (
	"fmt"
	"io"

	"github.com/kerbyfc/ipguard/internal/config"
)

// reporter печатает по строке на шаг: `+` — сделано, `=` — уже так.
type reporter struct {
	out io.Writer
}

// line печатает строку отчёта.
func (report reporter) line(text string) {
	_, _ = fmt.Fprintln(report.out, text)
}

// step печатает итог шага.
func (report reporter) step(name string, change Change) {
	if change.Note == "" {
		return
	}

	mark := "="
	if change.Done {
		mark = "+"
	}

	_, _ = fmt.Fprintf(report.out, "  %s %-12s %s\n", mark, name, change.Note)
}

// ending печатает, что осталось сделать владельцу руками.
func (report reporter) ending(paths Paths, settings config.Settings, mechanism string) {
	report.line("")
	report.line("proxy listens on http://claude:<secret>@" + settings.ListenAddr())
	report.line("autostart         " + mechanism)
	report.line("journal           " + settings.LogPath)
	report.line("")
	report.line("add the proxy to claude:  ipguard enable   (then restart claude)")
	report.line("drop the proxy:           ipguard disable")
	report.line("drop the autostart:       ipguard uninstall")
	report.line("settings:                 " + paths.Config)
}

// ended печатает, что проверить после правки настроек Claude Code. Сам секрет в терминал не
// идёт: он лежит в файле настроек сторожа и в `env` настроек claude.
func (report reporter) ended(settings config.Settings, path string) {
	report.line("")
	report.line("restart claude: environment variables are read once at startup")
	report.line("value: http://" + proxyUser + ":<secret>@" + settings.ListenAddr())
	report.line("file:  " + path)
	report.line("verdict check: ipguard status")
}
