package proxy_test

import (
	"bytes"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"testing"

	"github.com/kerbyfc/ipguard/internal/proxy"
)

const (
	// journalLimit — предел размера журнала в тестах: несколько строк, чтобы ротация
	// случилась на глазах.
	journalLimit = 160
	// journalKeepAll — столько поколений, что ни одно не снесётся: тесты целости строк
	// смотрят на сдвиг, а не на снос самого старого файла.
	journalKeepAll = 100
)

// TestJournalRotatesBySize: журнал сторожа живёт годами, поэтому при переполнении он
// переименовывается в `.1`, прежние сдвигаются, а старше keep штук не остаётся.
func TestJournalRotatesBySize(t *testing.T) {
	t.Parallel()

	path := filepath.Join(t.TempDir(), "proxy.log")

	journal, err := proxy.OpenJournal(path, journalLimit, 2, nil)
	if err != nil {
		t.Fatalf("open journal: %v", err)
	}

	for index := range 20 {
		journal.Printf("blocked request %d", index)
	}

	err = journal.Close()
	if err != nil {
		t.Fatalf("close journal: %v", err)
	}

	for _, name := range []string{path, path + ".1", path + ".2"} {
		info, statErr := os.Stat(name)
		if statErr != nil {
			t.Fatalf("stat %s: %v", name, statErr)
		}

		if info.Size() > journalLimit {
			t.Fatalf("%s grew to %d bytes over the %d limit", name, info.Size(), journalLimit)
		}
	}

	_, err = os.Stat(path + ".3")
	if !os.IsNotExist(err) {
		t.Fatalf("stat %s.3 gave %v, want the oldest file dropped", path, err)
	}

	content, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read journal: %v", err)
	}

	if !strings.Contains(string(content), "blocked request 19") {
		t.Fatalf("live journal %q has no last line", content)
	}
}

// TestJournalContinuesAfterReopen: перезапуск службы не теряет накопленный размер — иначе
// файл рос бы без ротации между перезапусками.
func TestJournalContinuesAfterReopen(t *testing.T) {
	t.Parallel()

	path := filepath.Join(t.TempDir(), "proxy.log")

	for range 2 {
		journal, err := proxy.OpenJournal(path, journalLimit, 2, nil)
		if err != nil {
			t.Fatalf("open journal: %v", err)
		}

		for index := range 3 {
			journal.Printf("blocked request %d", index)
		}

		err = journal.Close()
		if err != nil {
			t.Fatalf("close journal: %v", err)
		}
	}

	_, err := os.Stat(path + ".1")
	if err != nil {
		t.Fatalf("stat %s.1 after reopen: %v", path, err)
	}
}

// TestJournalRejectsBadRotation: предел размера и число файлов — настройки владельца, и
// негодные значения отбиваются, а не отключают ротацию молча.
func TestJournalRejectsBadRotation(t *testing.T) {
	t.Parallel()

	cases := map[string]struct {
		maxBytes int64
		keep     int
	}{
		"нулевой предел":   {maxBytes: 0, keep: 3},
		"без файлов":       {maxBytes: journalLimit, keep: 0},
		"предел со знаком": {maxBytes: -1, keep: 3},
	}

	for name, item := range cases {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			path := filepath.Join(t.TempDir(), "proxy.log")

			_, err := proxy.OpenJournal(path, item.maxBytes, item.keep, nil)
			if !errors.Is(err, proxy.ErrJournal) {
				t.Fatalf("open journal gave %v, want a journal error", err)
			}
		})
	}
}

// TestJournalKeepsEveryLineOnRotation: ротация — сдвиг файлов, и ни одна строка при нём не
// теряется и не удваивается. Это главное обещание журнала: по нему владелец читает, почему
// сторож держал трафик.
func TestJournalKeepsEveryLineOnRotation(t *testing.T) {
	t.Parallel()

	path := filepath.Join(t.TempDir(), "proxy.log")

	// keep больше, чем поколений наберётся: тест о потере строк на сдвиге, а не о сносе
	// самого старого файла — его проверяет TestJournalRotatesBySize.
	journal, err := proxy.OpenJournal(path, journalLimit, journalKeepAll, nil)
	if err != nil {
		t.Fatalf("open journal: %v", err)
	}

	const lines = 60

	for index := range lines {
		journal.Printf("blocked request %d", index)
	}

	err = journal.Close()
	if err != nil {
		t.Fatalf("close journal: %v", err)
	}

	written := readJournalLines(t, path)
	if len(written) != lines {
		t.Fatalf("journal holds %d lines, want %d: rotation lost or doubled lines", len(written), lines)
	}

	for index := range lines {
		message := fmt.Sprintf("blocked request %d", index)

		if written[message] != 1 {
			t.Fatalf("line %q appears %d times across the journal files", message, written[message])
		}
	}
}

// TestJournalKeepsEveryLineFromManyWriters: строки журнала пишут обработчики соединений из
// разных горутин, и ротация идёт под замком именно поэтому — ни одна строка не пропадает и не
// задваивается, когда писателей много.
func TestJournalKeepsEveryLineFromManyWriters(t *testing.T) {
	t.Parallel()

	path := filepath.Join(t.TempDir(), "proxy.log")

	journal, err := proxy.OpenJournal(path, journalLimit, journalKeepAll, nil)
	if err != nil {
		t.Fatalf("open journal: %v", err)
	}

	const (
		writers = 8
		each    = 12
	)

	var group sync.WaitGroup

	for writer := range writers {
		group.Add(1)

		go func() {
			defer group.Done()

			for index := range each {
				journal.Printf("writer %d line %d", writer, index)
			}
		}()
	}

	group.Wait()

	err = journal.Close()
	if err != nil {
		t.Fatalf("close journal: %v", err)
	}

	written := readJournalLines(t, path)
	if len(written) != writers*each {
		t.Fatalf("journal holds %d lines, want %d", len(written), writers*each)
	}

	for writer := range writers {
		for index := range each {
			message := fmt.Sprintf("writer %d line %d", writer, index)

			if written[message] != 1 {
				t.Fatalf("line %q appears %d times", message, written[message])
			}
		}
	}
}

// TestJournalMirrorsBeforeFile: зеркало (stderr при запуске в первом плане) получает строку
// раньше файла — отказ файла не должен отнимать у владельца единственный оставшийся вывод.
// Под службой зеркала нет: её вывод никто не ротирует.
func TestJournalMirrorsBeforeFile(t *testing.T) {
	t.Parallel()

	path := filepath.Join(t.TempDir(), "proxy.log")
	mirror := &bytes.Buffer{}

	journal, err := proxy.OpenJournal(path, journalLimit, 2, mirror)
	if err != nil {
		t.Fatalf("open journal: %v", err)
	}

	journal.Printf("blocked request to %s", "api.anthropic.com")

	err = journal.Close()
	if err != nil {
		t.Fatalf("close journal: %v", err)
	}

	if !strings.Contains(mirror.String(), "blocked request to api.anthropic.com") {
		t.Fatalf("mirror %q has no journal line", mirror.String())
	}

	content, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read journal: %v", err)
	}

	if !strings.Contains(string(content), "blocked request to api.anthropic.com") {
		t.Fatalf("journal file %q has no line", content)
	}
}

// TestJournalFallsOnBrokenRotation: сорвавшаяся ротация — нарушенный инвариант «сторож с
// журналом», и она роняет процесс паникой, а не оставляет сторожа работать вслепую.
func TestJournalFallsOnBrokenRotation(t *testing.T) {
	t.Parallel()

	directory := t.TempDir()
	path := filepath.Join(directory, "proxy.log")

	journal, err := proxy.OpenJournal(path, journalLimit, 1, nil)
	if err != nil {
		t.Fatalf("open journal: %v", err)
	}

	defer func() { _ = journal.Close() }()

	// Каталог на месте прежнего поколения: переименовать в него файл нельзя, и сдвиг сорвётся.
	err = os.MkdirAll(path+".1", 0o700)
	if err != nil {
		t.Fatalf("mkdir %s.1: %v", path, err)
	}

	err = os.WriteFile(filepath.Join(path+".1", "busy"), []byte("x"), 0o600)
	if err != nil {
		t.Fatalf("write into %s.1: %v", path, err)
	}

	defer func() {
		problem := recover()
		if problem == nil {
			t.Error("broken rotation left the guard running without a journal")
		}
	}()

	for index := range 20 {
		journal.Printf("blocked request %d", index)
	}
}

// readJournalLines — сколько раз каждая строка встречается во всех поколениях журнала:
// нынешнем файле и сдвинутых `.1`, `.2` и дальше.
func readJournalLines(t *testing.T, path string) map[string]int {
	t.Helper()

	lines := map[string]int{}

	for index := 0; ; index++ {
		name := path
		if index > 0 {
			name = path + "." + strconv.Itoa(index)
		}

		content, err := os.ReadFile(name)
		if os.IsNotExist(err) {
			return lines
		}

		if err != nil {
			t.Fatalf("read %s: %v", name, err)
		}

		for _, line := range strings.Split(strings.TrimRight(string(content), "\n"), "\n") {
			if line == "" {
				continue
			}

			// Строка журнала — дата, время и текст: сверяется текст.
			fields := strings.SplitN(line, " ", 3)
			if len(fields) != 3 {
				t.Fatalf("journal line %q has no message", line)
			}

			lines[fields[2]]++
		}
	}
}
