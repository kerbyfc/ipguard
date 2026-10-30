package proxy

import (
	"context"
	"fmt"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/kerbyfc/ipguard/internal/guard"
	"github.com/kerbyfc/ipguard/internal/seen"
)

// idleChecker — вердикт, которого этот тест не спрашивает: прокси требует источник вердикта,
// а память об исключениях проверяется без единого соединения.
type idleChecker struct{}

// Verdict отдаёт пропуск: до него тест не доходит.
func (idleChecker) Verdict(context.Context) (guard.Verdict, error) {
	return guard.Verdict{Kind: guard.KindOK, IP: "203.0.113.7", LastError: "", At: time.Now()}, nil
}

// TestTellStopsAtLimit: память об исключениях не растёт без предела. Имён у исключений
// сколько угодно — каждый частный адрес и любой поддомен шаблона, — поэтому предел тот же,
// что у таблицы защищаемых хостов, и о нём говорится один раз, а не молча.
func TestTellStopsAtLimit(t *testing.T) {
	t.Parallel()

	journal := &strings.Builder{}
	server := serverForTell(t, journal)

	for index := range seen.DefaultLimit + 5 {
		server.tell(fmt.Sprintf("host-%d.example.test", index))
	}

	if len(server.told) != seen.DefaultLimit {
		t.Fatalf("the exception log holds %d names, want the limit %d", len(server.told), seen.DefaultLimit)
	}

	if strings.Count(journal.String(), "exception log limit") != 1 {
		t.Fatalf("the limit was told %d times, want once:\n%s",
			strings.Count(journal.String(), "exception log limit"), journal.String())
	}

	if server.tell("host-0.example.test") {
		t.Fatal("a known exception was reported as new")
	}
}

// serverForTell поднимает слушателя на свободном порту loopback: памяти об исключениях
// нужен собранный прокси, а не литерал.
func serverForTell(t *testing.T, journal *strings.Builder) *Server {
	t.Helper()

	table, err := seen.Open(seen.Config{
		Path:  filepath.Join(t.TempDir(), "hosts.tsv"),
		Limit: seen.DefaultLimit,
		Flush: seen.DefaultFlush,
		Now:   time.Now,
		Logf:  func(string, ...any) {},
	})
	if err != nil {
		t.Fatalf("open seen hosts: %v", err)
	}

	t.Cleanup(func() { _ = table.Close() })

	server, err := New(Config{
		Addr:           "127.0.0.1:0",
		Secret:         "tell-secret",
		UpstreamProxy:  "",
		ExpectedIP:     "203.0.113.7",
		CheckURL:       "https://icanhazip.test/",
		UnguardedHosts: nil,
		Budget:         time.Minute,
		Checker:        idleChecker{},
		Journal:        NewJournal(journal),
		Seen:           table,
	})
	if err != nil {
		t.Fatalf("new proxy: %v", err)
	}

	t.Cleanup(func() { _ = server.Close() })

	return server
}
