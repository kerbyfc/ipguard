package cli

import (
	"fmt"
	"io"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/spf13/cobra"
	"github.com/spf13/viper"

	"github.com/kerbyfc/ipguard/internal/install"
	"github.com/kerbyfc/ipguard/internal/proxy"
)

const (
	// humanLayout — время для человека: часовой пояс машины, без смещения и без `T`.
	// Машинный договор `/status` при этом остаётся RFC 3339 — очеловечивает сама команда.
	humanLayout = "2006-01-02 15:04:05"

	// seenIndent — отступ таблицы, seenGap — просвет между колонками.
	seenIndent = "  "
	seenGap    = "  "

	headHost  = "host"
	headHits  = "requests"
	headFirst = "first seen"
	headLast  = "last seen"
)

// seenRow — строка таблицы защищаемых хостов, готовая к печати.
type seenRow struct {
	host  string
	hits  string
	first string
	last  string
}

// newStatus — команда «спросить вердикт у поднятого сервиса».
func newStatus(reader *viper.Viper) *cobra.Command {
	//nolint:exhaustruct // заданы имя, описание и обработчик, остальное — cobra
	return &cobra.Command{
		Use:   "status",
		Short: "Ask the running service for the verdict: exit code 0 on a pass, 3 on a block",
		Args:  cobra.NoArgs,
		RunE: func(command *cobra.Command, _ []string) error {
			return runStatus(command, reader)
		},
	}
}

// runStatus печатает вердикт поднятого сервиса и обе стороны границы охраны: это и есть
// способ увидеть, что сторож делает сейчас, не перезапуская установку.
func runStatus(command *cobra.Command, reader *viper.Viper) error {
	settings, err := loadSettings(reader)
	if err != nil {
		return err
	}

	err = settings.RequireSecret()
	if err != nil {
		return exitError{code: ExitUsage, message: err.Error()}
	}

	view, err := install.LocalProbe(command.Context(), settings)
	if err != nil {
		return exitError{code: ExitFailure, message: err.Error()}
	}

	checked, err := humanTime(view.CheckedAt)
	if err != nil {
		return err
	}

	out := command.OutOrStdout()

	_, _ = fmt.Fprintf(
		out,
		"verdict %s, external IP %s, expected %s, checked at %s\n",
		view.Verdict, view.IP, view.ExpectedIP, checked,
	)

	err = printBoundary(out, view)
	if err != nil {
		return err
	}

	if !view.Allowed {
		return exitError{code: ExitBlocked, message: view.Message}
	}

	return nil
}

// printBoundary печатает обе стороны границы: сначала исключения из настройки, затем
// защищаемые хосты таблицей. Порядок — перевёрнутые метки имени, его задаёт сам сервис.
func printBoundary(out io.Writer, view proxy.StatusView) error {
	_, _ = fmt.Fprintf(out, "exceptions (%d):\n", len(view.UnguardedHosts))

	for _, pattern := range view.UnguardedHosts {
		_, _ = fmt.Fprintln(out, seenIndent+pattern)
	}

	_, _ = fmt.Fprintf(out, "guarded hosts (%d):\n", len(view.SeenHosts))

	if view.SeenLimitReached {
		_, _ = fmt.Fprintln(out, seenIndent+"! the recorded limit is reached: new hosts are not recorded")
	}

	return printSeen(out, view.SeenHosts)
}

// printSeen печатает таблицу защищаемых хостов: ширины колонок — по данным, счётчик прижат
// вправо, шапка идёт только когда есть строки.
func printSeen(out io.Writer, views []proxy.SeenHostView) error {
	rows, err := seenRows(views)
	if err != nil {
		return err
	}

	if len(rows) == 0 {
		return nil
	}

	host, hits, first := seenWidths(rows)

	_, _ = fmt.Fprintln(out, seenLine(
		padRight(headHost, host), padLeft(headHits, hits), padRight(headFirst, first), headLast,
	))

	for _, row := range rows {
		_, _ = fmt.Fprintln(out, seenLine(
			padRight(row.host, host), padLeft(row.hits, hits), padRight(row.first, first), row.last,
		))
	}

	return nil
}

// seenRows переводит ответ сервиса в строки таблицы и очеловечивает время.
func seenRows(views []proxy.SeenHostView) ([]seenRow, error) {
	rows := make([]seenRow, 0, len(views))

	for _, view := range views {
		first, err := humanTime(view.FirstSeen)
		if err != nil {
			return nil, err
		}

		last, err := humanTime(view.LastSeen)
		if err != nil {
			return nil, err
		}

		rows = append(rows, seenRow{
			host:  view.Host,
			hits:  strconv.FormatInt(view.Hits, 10),
			first: first,
			last:  last,
		})
	}

	return rows, nil
}

// seenWidths — ширины колонок по заголовкам и данным.
func seenWidths(rows []seenRow) (int, int, int) {
	host, hits, first := width(headHost), width(headHits), width(headFirst)

	for _, row := range rows {
		host = max(host, width(row.host))
		hits = max(hits, width(row.hits))
		first = max(first, width(row.first))
	}

	return host, hits, first
}

// seenLine собирает строку таблицы: отступ и просветы между колонками. Последняя колонка не
// добивается — пробелы в конце строки никому не нужны.
func seenLine(host, hits, first, last string) string {
	return seenIndent + host + seenGap + hits + seenGap + first + seenGap + last
}

// humanTime переводит время сервиса в человеческий вид в часовом поясе машины, на которой
// запущена команда. Сервис отдаёт RFC 3339 — это договор; пришло другое — отказ с причиной,
// а не печать сырой строки.
func humanTime(raw string) (string, error) {
	moment, err := time.Parse(time.RFC3339, raw)
	if err != nil {
		return "", exitError{
			code:    ExitFailure,
			message: fmt.Sprintf("the service gave the time %q, which is not RFC 3339: %v", raw, err),
		}
	}

	// Отступление названо прямо: `time.Now().Location()` — это и есть `time.Local`, пояс
	// машины, на которой запущена команда. Его требует постановка: владелец читает вывод
	// здесь и сейчас. Линтер `gosmopolitan` запрещает сам `time.Local` как недружественный
	// к переводу, но вывод команды и не переводится; обходить линтер директивой `//nolint`
	// нельзя правилом репозитория, поэтому пояс берётся у процесса, а не у константы.
	return moment.In(time.Now().Location()).Format(humanLayout), nil
}

// padRight добивает строку пробелами справа, padLeft — слева: ширина считается рунами, а не
// байтами — имена хостов бывают не ASCII.
func padRight(text string, to int) string {
	return text + pad(to-width(text))
}

// padLeft прижимает строку вправо.
func padLeft(text string, to int) string {
	return pad(to-width(text)) + text
}

// pad — строка из count пробелов.
func pad(count int) string {
	if count < 1 {
		return ""
	}

	return strings.Repeat(" ", count)
}

// width — ширина строки в рунах.
func width(text string) int {
	return utf8.RuneCountInString(text)
}
