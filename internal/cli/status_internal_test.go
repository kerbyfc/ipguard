package cli

import (
	"bytes"
	"errors"
	"regexp"
	"strings"
	"testing"
	"time"
	"unicode/utf8"

	"github.com/kerbyfc/ipguard/internal/proxy"
)

// humanShape — время для человека: дата и время через пробел, без `T` и без смещения.
var humanShape = regexp.MustCompile(`^\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}$`)

// TestPrintBoundaryShowsBothSides: `status` печатает сначала исключения, затем защищаемые
// хосты: по этому выводу владелец и видит обе стороны границы.
func TestPrintBoundaryShowsBothSides(t *testing.T) {
	t.Parallel()

	out := &bytes.Buffer{}

	err := printBoundary(out, boundaryView())
	if err != nil {
		t.Fatalf("print: %v", err)
	}

	text := out.String()

	for _, want := range []string{
		"exceptions (2):",
		"*.anthropic.com",
		"guarded hosts (2):",
		"the recorded limit is reached",
		"api.anthropic.com",
		"models.example.test",
	} {
		if !strings.Contains(text, want) {
			t.Fatalf("output does not hold %q:\n%s", want, text)
		}
	}

	// Имени настройки в заголовке исключений нет, как и слова «встреченные»: заголовки английские.
	if strings.Contains(text, "unguarded_hosts") || strings.Contains(text, "encountered") {
		t.Fatalf("output holds a stale heading:\n%s", text)
	}

	if strings.Index(text, "exceptions (") > strings.Index(text, "guarded hosts") {
		t.Fatalf("exceptions are printed after the guarded hosts:\n%s", text)
	}
}

// TestPrintBoundaryAlignsTable: колонки выровнены, счётчик прижат вправо, а ширины считаются
// рунами — заголовки русские, и по байтам таблица разъехалась бы.
func TestPrintBoundaryAlignsTable(t *testing.T) {
	t.Parallel()

	out := &bytes.Buffer{}

	err := printBoundary(out, boundaryView())
	if err != nil {
		t.Fatalf("print: %v", err)
	}

	rows := tableLines(t, out.String())

	head := rows[0]
	if !strings.HasPrefix(head, seenIndent+headHost) {
		t.Fatalf("table head %q does not start with the host column", head)
	}

	hitsEnd := runeIndex(head, headHits) + width(headHits)
	firstStart := runeIndex(head, headFirst)
	lastStart := runeIndex(head, headLast)

	for _, row := range rows[1:] {
		runes := []rune(row)

		// Счётчик прижат вправо: его последняя цифра стоит ровно на правом краю колонки.
		if runes[hitsEnd-1] == ' ' {
			t.Fatalf("row %q does not press the counter to the right edge of its column", row)
		}

		if runeIndex(row, firstOf(row)) != firstStart {
			t.Fatalf("row %q starts the first-seen column at %d, want %d", row, runeIndex(row, firstOf(row)), firstStart)
		}

		if string(runes[lastStart:]) != lastOf(row) {
			t.Fatalf("row %q does not start the last-seen column at %d", row, lastStart)
		}
	}
}

// TestPrintBoundaryHeadsOnlyWithRows: шапка нужна таблице, а не пустому списку.
func TestPrintBoundaryHeadsOnlyWithRows(t *testing.T) {
	t.Parallel()

	view := proxy.StatusView{ //nolint:exhaustruct // печати нужны только обе стороны границы
		UnguardedHosts:   nil,
		SeenHosts:        nil,
		SeenLimitReached: false,
	}

	out := &bytes.Buffer{}

	err := printBoundary(out, view)
	if err != nil {
		t.Fatalf("print: %v", err)
	}

	text := out.String()
	if !strings.Contains(text, "guarded hosts (0):") {
		t.Fatalf("output does not hold the empty table heading:\n%s", text)
	}

	if strings.Contains(text, headHits) {
		t.Fatalf("an empty table got a head:\n%s", text)
	}
}

// TestHumanTime: время печатается в часовом поясе машины, без `T` и без смещения; не RFC
// 3339 из сервиса — отказ с причиной, а не печать сырой строки.
func TestHumanTime(t *testing.T) {
	t.Parallel()

	moment := time.Date(2026, time.October, 20, 11, 40, 25, 0, time.FixedZone("MSK", 3*60*60))

	got, err := humanTime(moment.Format(time.RFC3339))
	if err != nil {
		t.Fatalf("human time: %v", err)
	}

	if !humanShape.MatchString(got) {
		t.Fatalf("time %q is not the human shape", got)
	}

	here := moment.In(time.Now().Location()).Format(humanLayout)
	if got != here {
		t.Fatalf("time %q, want the same instant in the zone of this machine %q", got, here)
	}

	_, err = humanTime("вчера вечером")

	var coded exitError
	if !errors.As(err, &coded) || coded.code != ExitFailure {
		t.Fatalf("human time of a broken string gave %v, want exit code %d", err, ExitFailure)
	}

	if !strings.Contains(coded.message, "RFC 3339") {
		t.Fatalf("refusal %q does not name the contract", coded.message)
	}
}

// TestPrintBoundaryRefusesBrokenTime: сервис отдал время не по договору — отказ, а не сырая
// строка в таблице.
func TestPrintBoundaryRefusesBrokenTime(t *testing.T) {
	t.Parallel()

	view := proxy.StatusView{ //nolint:exhaustruct // печати нужны только защищаемые хосты
		UnguardedHosts: nil,
		SeenHosts: []proxy.SeenHostView{
			{Host: "api.anthropic.com", FirstSeen: "позавчера", LastSeen: "2026-10-20T11:37:39Z", Hits: 1},
		},
		SeenLimitReached: false,
	}

	err := printBoundary(&bytes.Buffer{}, view)
	if err == nil {
		t.Fatal("a broken time was printed as is")
	}

	if !strings.Contains(err.Error(), "RFC 3339") {
		t.Fatalf("refusal %q does not name the contract", err)
	}
}

// boundaryView — ответ сервиса для печати: разные длины имён и счётчиков, чтобы по выводу
// была видна и ширина колонок, и прижатый вправо счётчик.
func boundaryView() proxy.StatusView {
	return proxy.StatusView{ //nolint:exhaustruct // печати нужны только обе стороны границы
		UnguardedHosts: []string{"*.anthropic.com", "zebra.example.test"},
		SeenHosts: []proxy.SeenHostView{
			{
				Host:      "api.anthropic.com",
				FirstSeen: "2026-10-20T10:32:32Z",
				LastSeen:  "2026-10-20T11:37:39Z",
				Hits:      275,
			},
			{
				Host:      "models.example.test",
				FirstSeen: "2026-10-20T10:34:46Z",
				LastSeen:  "2026-10-20T11:35:19Z",
				Hits:      13,
			},
		},
		SeenLimitReached: true,
	}
}

// tableLines — строки таблицы: шапка и строки хостов.
func tableLines(t *testing.T, text string) []string {
	t.Helper()

	lines := strings.Split(strings.TrimRight(text, "\n"), "\n")

	for number, line := range lines {
		if strings.HasPrefix(line, seenIndent+headHost) {
			return lines[number:]
		}
	}

	t.Fatalf("output has no table head:\n%s", text)

	return nil
}

// firstOf и lastOf — время первой и последней встречи в строке таблицы.
func firstOf(row string) string {
	return strings.Fields(row)[2] + " " + strings.Fields(row)[3]
}

// lastOf — последняя пара полей строки.
func lastOf(row string) string {
	fields := strings.Fields(row)

	return fields[4] + " " + fields[5]
}

// runeIndex — позиция подстроки в рунах; -1, если её нет.
func runeIndex(line, sub string) int {
	at := strings.Index(line, sub)
	if at < 0 {
		return -1
	}

	return utf8.RuneCountInString(line[:at])
}
