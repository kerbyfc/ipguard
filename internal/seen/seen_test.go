package seen_test

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/kerbyfc/ipguard/internal/seen"
)

// testClock — часы теста: таблицу трогает и горутина срока записи, поэтому время под замком.
type testClock struct {
	mutex sync.Mutex
	now   time.Time
}

// Now — нынешнее время теста.
func (clock *testClock) Now() time.Time {
	clock.mutex.Lock()
	defer clock.mutex.Unlock()

	return clock.now
}

// advance двигает часы теста.
func (clock *testClock) advance(step time.Duration) {
	clock.mutex.Lock()
	defer clock.mutex.Unlock()

	clock.now = clock.now.Add(step)
}

// testJournal — строки журнала теста.
type testJournal struct {
	mutex sync.Mutex
	lines []string
}

// Printf пишет строку журнала.
func (journal *testJournal) Printf(format string, args ...any) {
	journal.mutex.Lock()
	defer journal.mutex.Unlock()

	journal.lines = append(journal.lines, strings.TrimSpace(fmt.Sprintf(format, args...)))
}

// all — копия строк журнала.
func (journal *testJournal) all() []string {
	journal.mutex.Lock()
	defer journal.mutex.Unlock()

	lines := make([]string, len(journal.lines))
	copy(lines, journal.lines)

	return lines
}

// TestNoteCountsHitsAndSurvivesRestart: счётчик растёт на каждом обращении, а накопленное
// переживает перезапуск службы — иначе статистика обнулялась бы каждым запуском.
func TestNoteCountsHitsAndSurvivesRestart(t *testing.T) {
	t.Parallel()

	path := filepath.Join(t.TempDir(), "hosts.tsv")
	clock := &testClock{mutex: sync.Mutex{}, now: time.Date(2026, time.October, 20, 9, 0, 0, 0, time.UTC)}
	store := open(t, path, clock)

	first := store.Note("api.anthropic.com:443")
	if !first {
		t.Fatal("the first encounter was not reported as first")
	}

	clock.advance(5 * time.Minute)

	again := store.Note("API.anthropic.com")
	if again {
		t.Fatal("the second encounter was reported as first")
	}

	store.Note("second.anthropic.com")

	err := store.Close()
	if err != nil {
		t.Fatalf("close: %v", err)
	}

	reopened := open(t, path, clock)

	entries := reopened.Entries()
	if len(entries) != 2 {
		t.Fatalf("entries after restart %v, want two", entries)
	}

	if entries[0].Host != "api.anthropic.com" || entries[0].Hits != 2 {
		t.Fatalf("entry %+v, want api.anthropic.com with two hits", entries[0])
	}

	if !entries[0].Last.After(entries[0].First) {
		t.Fatalf("last seen %s is not after first seen %s", entries[0].Last, entries[0].First)
	}

	if entries[1].Host != "second.anthropic.com" || entries[1].Hits != 1 {
		t.Fatalf("entry %+v, want the second host with one hit", entries[1])
	}
}

// TestFlushWaitsForInterval: файл перезаписывается целиком, поэтому не чаще раза в срок;
// между сроками накопленное живёт в памяти, а при остановке уходит на диск.
func TestFlushWaitsForInterval(t *testing.T) {
	t.Parallel()

	path := filepath.Join(t.TempDir(), "hosts.tsv")
	clock := &testClock{mutex: sync.Mutex{}, now: time.Date(2026, time.October, 20, 9, 0, 0, 0, time.UTC)}
	store := open(t, path, clock)

	store.Note("early.test")

	_, err := os.Stat(path)
	if !os.IsNotExist(err) {
		t.Fatalf("the table was written before the interval passed: %v", err)
	}

	clock.advance(2 * time.Second)
	store.Note("late.test")

	content, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read table: %v", err)
	}

	if !strings.Contains(string(content), "early.test") || !strings.Contains(string(content), "late.test") {
		t.Fatalf("table %q holds neither host", content)
	}

	err = store.Close()
	if err != nil {
		t.Fatalf("close: %v", err)
	}
}

// TestCloseFlushesLastSecond: остановка службы сбрасывает таблицу без оглядки на срок.
func TestCloseFlushesLastSecond(t *testing.T) {
	t.Parallel()

	path := filepath.Join(t.TempDir(), "hosts.tsv")
	clock := &testClock{mutex: sync.Mutex{}, now: time.Date(2026, time.October, 20, 9, 0, 0, 0, time.UTC)}
	store := open(t, path, clock)

	store.Note("only.test")

	err := store.Close()
	if err != nil {
		t.Fatalf("close: %v", err)
	}

	content, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read table: %v", err)
	}

	if !strings.Contains(string(content), "only.test\t2026-") {
		t.Fatalf("table %q does not hold the host", content)
	}
}

// TestLimitTellsOnce: предел числа записей не молчит — строка журнала один раз и признак
// предела; новые хосты в таблицу не попадают.
func TestLimitTellsOnce(t *testing.T) {
	t.Parallel()

	path := filepath.Join(t.TempDir(), "hosts.tsv")
	clock := &testClock{mutex: sync.Mutex{}, now: time.Date(2026, time.October, 20, 9, 0, 0, 0, time.UTC)}
	journal := &testJournal{mutex: sync.Mutex{}, lines: nil}

	store, err := seen.Open(seen.Config{
		Path:  path,
		Limit: 1,
		Flush: time.Second,
		Now:   clock.Now,
		Logf:  journal.Printf,
	})
	if err != nil {
		t.Fatalf("open: %v", err)
	}

	t.Cleanup(func() { _ = store.Close() })

	store.Note("first.test")
	store.Note("second.test")
	store.Note("third.test")

	if !store.LimitReached() {
		t.Fatal("the limit was not reported as reached")
	}

	if len(store.Entries()) != 1 {
		t.Fatalf("entries %v, want only the first host", store.Entries())
	}

	told := 0

	for _, line := range journal.all() {
		if strings.Contains(line, "seen hosts limit") {
			told++
		}
	}

	if told != 1 {
		t.Fatalf("the limit was told %d times, want once", told)
	}
}

// TestOldTableWithBorderColumnIsRead: прежний файл нёс колонку границы. Он читается и при
// первой же записи ложится в нынешнем виде — служба владельца не падает на своём файле.
func TestOldTableWithBorderColumnIsRead(t *testing.T) {
	t.Parallel()

	path := filepath.Join(t.TempDir(), "hosts.tsv")
	old := "# встреченные хосты сторожа: имя, граница, первая встреча, последняя встреча, обращений\n" +
		"api.anthropic.com\tguarded\t2026-10-20T09:00:00Z\t2026-10-20T09:05:00Z\t42\n" +
		"127.0.0.1\texempt\t2026-10-20T09:01:00Z\t2026-10-20T09:02:00Z\t7\n"

	err := os.WriteFile(path, []byte(old), 0o600)
	if err != nil {
		t.Fatalf("write table: %v", err)
	}

	clock := &testClock{mutex: sync.Mutex{}, now: time.Date(2026, time.October, 20, 10, 0, 0, 0, time.UTC)}
	store := open(t, path, clock)

	entries := store.Entries()
	if len(entries) != 2 {
		t.Fatalf("entries %+v, want both hosts of the old file", entries)
	}

	if entries[1].Host != "api.anthropic.com" || entries[1].Hits != 42 {
		t.Fatalf("entry %+v, want the counter of the old file", entries[1])
	}

	err = store.Close()
	if err != nil {
		t.Fatalf("close: %v", err)
	}

	content, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read table: %v", err)
	}

	if strings.Contains(string(content), "\tguarded\t") || strings.Contains(string(content), "\texempt\t") {
		t.Fatalf("the border column survived the rewrite:\n%s", content)
	}

	if !strings.Contains(string(content), "api.anthropic.com\t2026-10-20T09:00:00Z\t2026-10-20T09:05:00Z\t42") {
		t.Fatalf("the rewritten table lost the host:\n%s", content)
	}
}

// TestFilterDropsExceptions: хост, попавший в белый список позже, уходит из таблицы — иначе
// она говорила бы о защите, которой больше нет. Таблица при этом сразу уходит на диск.
func TestFilterDropsExceptions(t *testing.T) {
	t.Parallel()

	path := filepath.Join(t.TempDir(), "hosts.tsv")
	clock := &testClock{mutex: sync.Mutex{}, now: time.Date(2026, time.October, 20, 9, 0, 0, 0, time.UTC)}
	store := open(t, path, clock)

	for _, host := range []string{"api.anthropic.com", "models.example.test", "free.example.test"} {
		store.Note(host)
	}

	dropped, err := store.Filter(func(host string) bool { return host == "free.example.test" })
	if err != nil {
		t.Fatalf("filter: %v", err)
	}

	if dropped != 1 {
		t.Fatalf("dropped %d hosts, want one", dropped)
	}

	for _, entry := range store.Entries() {
		if entry.Host == "free.example.test" {
			t.Fatalf("the exception stayed in the table: %+v", store.Entries())
		}
	}

	content, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read table: %v", err)
	}

	if strings.Contains(string(content), "free.example.test") {
		t.Fatalf("the exception stayed in the file:\n%s", content)
	}

	idle, err := store.Filter(func(string) bool { return false })
	if err != nil || idle != 0 {
		t.Fatalf("a filter that drops nothing gave %d and %v", idle, err)
	}
}

// TestFilterTellsAboutWriteRefusal: записи убраны из памяти, но файл не переписался — об
// этом говорится отказом, а не словом «убраны»: на диске они ещё лежат.
func TestFilterTellsAboutWriteRefusal(t *testing.T) {
	t.Parallel()

	directory := t.TempDir()
	path := filepath.Join(directory, "hosts.tsv")
	clock := &testClock{mutex: sync.Mutex{}, now: time.Now()}
	store := open(t, path, clock)

	store.Note("free.example.test")

	err := os.RemoveAll(directory)
	if err != nil {
		t.Fatalf("remove directory: %v", err)
	}

	dropped, err := store.Filter(func(string) bool { return true })
	if dropped != 1 {
		t.Fatalf("dropped %d hosts, want one", dropped)
	}

	if !errors.Is(err, seen.ErrSeen) {
		t.Fatalf("filter gave %v, want a table error", err)
	}
}

// TestLegacyHeaderAloneIsRewritten: файл, в котором от прежнего вида осталась одна шапка,
// тоже приводится к нынешнему: иначе он так и лежал бы с враньём про снятую колонку.
func TestLegacyHeaderAloneIsRewritten(t *testing.T) {
	t.Parallel()

	path := filepath.Join(t.TempDir(), "hosts.tsv")
	old := "# встреченные хосты сторожа: имя, граница, первая встреча, последняя встреча, обращений\n"

	err := os.WriteFile(path, []byte(old), 0o600)
	if err != nil {
		t.Fatalf("write table: %v", err)
	}

	clock := &testClock{mutex: sync.Mutex{}, now: time.Now()}
	store := open(t, path, clock)

	err = store.Close()
	if err != nil {
		t.Fatalf("close: %v", err)
	}

	content, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read table: %v", err)
	}

	if strings.Contains(string(content), "граница") {
		t.Fatalf("the old head survived:\n%s", content)
	}

	if !strings.Contains(string(content), "guarded hosts of the guard") {
		t.Fatalf("the table got no current head:\n%s", content)
	}
}

// TestBrokenTableRefused: битая строка файла — отказ с номером строки, а не молчаливая
// потеря накопленного.
func TestBrokenTableRefused(t *testing.T) {
	t.Parallel()

	cases := map[string]string{
		"мало полей":     "api.test\t2026-10-20T09:00:00Z\n",
		"чужая граница":  "api.test\tmaybe\t2026-10-20T09:00:00Z\t2026-10-20T09:00:00Z\t1\n",
		"не время":       "api.test\tнедавно\t2026-10-20T09:00:00Z\t1\n",
		"не число":       "api.test\t2026-10-20T09:00:00Z\t2026-10-20T09:00:00Z\tмного\n",
		"счётчик пустой": "api.test\t2026-10-20T09:00:00Z\t2026-10-20T09:00:00Z\t0\n",
	}

	for name, body := range cases {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			path := filepath.Join(t.TempDir(), "hosts.tsv")

			writeErr := os.WriteFile(path, []byte(body), 0o600)
			if writeErr != nil {
				t.Fatalf("write table: %v", writeErr)
			}

			clock := &testClock{mutex: sync.Mutex{}, now: time.Now()}

			_, err := seen.Open(seen.Config{
				Path:  path,
				Limit: 10,
				Flush: time.Second,
				Now:   clock.Now,
				Logf:  func(string, ...any) {},
			})
			if !errors.Is(err, seen.ErrSeen) {
				t.Fatalf("open gave %v, want a table error", err)
			}

			if !strings.Contains(err.Error(), path+":1") {
				t.Fatalf("refusal %q does not name the file and line", err)
			}
		})
	}
}

// TestEntriesOrderedByReversedLabels: порядок — зона, домен, поддомен: хосты одного домена
// стоят рядом и в файле, и в ответе `/status`.
func TestEntriesOrderedByReversedLabels(t *testing.T) {
	t.Parallel()

	path := filepath.Join(t.TempDir(), "hosts.tsv")
	clock := &testClock{mutex: sync.Mutex{}, now: time.Now()}
	store := open(t, path, clock)

	for _, host := range []string{"bun.report", "storage.googleapis.com", "api.anthropic.com", "anthropic.com"} {
		store.Note(host)
	}

	want := []string{"anthropic.com", "api.anthropic.com", "storage.googleapis.com", "bun.report"}

	for index, entry := range store.Entries() {
		if entry.Host != want[index] {
			t.Fatalf("entry %d is %q, want %q", index, entry.Host, want[index])
		}
	}
}

// TestOpenRefusesBadConfig: нет значения — отказ с причиной, а не значение по умолчанию.
func TestOpenRefusesBadConfig(t *testing.T) {
	t.Parallel()

	directory := t.TempDir()
	clock := &testClock{mutex: sync.Mutex{}, now: time.Now()}

	cases := map[string]seen.Config{
		"без файла": {
			Path: "", Limit: 10, Flush: time.Second, Now: clock.Now, Logf: func(string, ...any) {},
		},
		"без предела": {
			Path: filepath.Join(directory, "hosts.tsv"), Limit: 0, Flush: time.Second,
			Now: clock.Now, Logf: func(string, ...any) {},
		},
		"без срока": {
			Path: filepath.Join(directory, "hosts.tsv"), Limit: 10, Flush: 0,
			Now: clock.Now, Logf: func(string, ...any) {},
		},
		"без часов": {
			Path: filepath.Join(directory, "hosts.tsv"), Limit: 10, Flush: time.Second,
			Now: nil, Logf: func(string, ...any) {},
		},
		"каталога нет": {
			Path: filepath.Join(directory, "absent", "hosts.tsv"), Limit: 10, Flush: time.Second,
			Now: clock.Now, Logf: func(string, ...any) {},
		},
	}

	for name, item := range cases {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			_, err := seen.Open(item)
			if !errors.Is(err, seen.ErrSeen) {
				t.Fatalf("open gave %v, want a table error", err)
			}
		})
	}
}

// open поднимает таблицу теста и закрывает её в конце.
func open(t *testing.T, path string, clock *testClock) *seen.Store {
	t.Helper()

	store, err := seen.Open(seen.Config{
		Path:  path,
		Limit: 10,
		Flush: time.Second,
		Now:   clock.Now,
		Logf:  func(string, ...any) {},
	})
	if err != nil {
		t.Fatalf("open table: %v", err)
	}

	t.Cleanup(func() { _ = store.Close() })

	return store
}
