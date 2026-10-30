package proxy_test

import (
	"context"
	"encoding/json"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/kerbyfc/ipguard/internal/guard"
	"github.com/kerbyfc/ipguard/internal/proxy"
	"github.com/kerbyfc/ipguard/internal/seen"
)

// TestUnlistedHostWaitsForVerdict: граница перевёрнута — хост, которого нет ни в одном
// исключении, ждёт вердикта и при несовпавшем IP закрыт. Прежде такой хост шёл мимо
// проверки, и это была дыра в охране.
func TestUnlistedHostWaitsForVerdict(t *testing.T) {
	t.Parallel()

	server := startProxyWithUnguarded(t, mismatchChecker(), "", nil)

	connection, _, response := rawConnect(t, server.Addr(), "unlisted.example.test:443", basicHeader(testSecret))

	defer func() { _ = response.Body.Close() }()
	defer func() { _ = connection.Close() }()

	if response.StatusCode != http.StatusForbidden {
		t.Fatalf("status %d for a host outside every exception, want 403", response.StatusCode)
	}
}

// TestRequestWithoutHostStaysGuarded: запрос без имени хоста остаётся под вердиктом — отказ
// по умолчанию закрытый. В таблицу встреченных такой запрос не попадает: записывать нечего.
func TestRequestWithoutHostStaysGuarded(t *testing.T) {
	t.Parallel()

	server, _, table := startProxyWithSeen(t, mismatchChecker(), "", nil)

	connection, _, response := rawConnect(t, server.Addr(), ":443", basicHeader(testSecret))

	defer func() { _ = response.Body.Close() }()
	defer func() { _ = connection.Close() }()

	if response.StatusCode != http.StatusForbidden {
		t.Fatalf("status %d for a request without a host, want 403", response.StatusCode)
	}

	if len(table.Entries()) != 0 {
		t.Fatalf("seen hosts %+v, want none: there is no host to record", table.Entries())
	}
}

// TestWhitelistPatternPassesWithoutCheck: шаблон белого списка снимает охрану с хоста, и
// вердикт для него не запрашивается вовсе.
func TestWhitelistPatternPassesWithoutCheck(t *testing.T) {
	t.Parallel()

	checker := &countingChecker{calls: atomic.Int64{}}
	server := startProxyWithUnguarded(t, checker, "", []string{"*.example.test"})

	connection, _, response := rawConnect(t, server.Addr(), "api.example.test:1", basicHeader(testSecret))

	defer func() { _ = response.Body.Close() }()
	defer func() { _ = connection.Close() }()

	if response.StatusCode == http.StatusForbidden {
		t.Fatal("a whitelisted host was blocked")
	}

	if checker.calls.Load() != 0 {
		t.Fatalf("a whitelisted host caused %d checks, want 0", checker.calls.Load())
	}
}

// TestSeenTableHoldsGuardedOnly: таблица копит только то, что сторож защищает. Исключения в
// неё не идут: по ней отвечают на вопрос «что под вердиктом», а не «куда ходили».
func TestSeenTableHoldsGuardedOnly(t *testing.T) {
	t.Parallel()

	server, _, table := startProxyWithSeen(t, mismatchChecker(), "", []string{"free.example.test"})

	for range 2 {
		closeConnect(t, server.Addr(), "watched.example.test:443")
	}

	closeConnect(t, server.Addr(), "127.0.0.1:1")
	closeConnect(t, server.Addr(), "free.example.test:1")

	entries := table.Entries()
	if len(entries) != 1 {
		t.Fatalf("seen hosts %+v, want only the guarded one", entries)
	}

	if entries[0].Host != "watched.example.test" || entries[0].Hits != 2 {
		t.Fatalf("entry %+v, want the guarded host with two hits", entries[0])
	}
}

// TestStatusShowsBoundary: `/status` отдаёт обе стороны границы — исключения из настройки и
// накопленные хосты со счётчиками: иначе владелец не увидел бы, что идёт мимо проверки.
func TestStatusShowsBoundary(t *testing.T) {
	t.Parallel()

	server := startProxyWithUnguarded(t, okChecker(), "", []string{"zebra.example.test", "*.anthropic.com"})

	closeConnect(t, server.Addr(), "guarded.example.test:1")

	view := askStatus(t, server.Addr())

	checkOrder(t, view.UnguardedHosts, []string{"*.anthropic.com", "zebra.example.test"})

	if len(view.SeenHosts) != 1 || view.SeenHosts[0].Host != "guarded.example.test" {
		t.Fatalf("seen hosts %+v, want the guarded host", view.SeenHosts)
	}

	if view.SeenHosts[0].Hits != 1 {
		t.Fatalf("seen host %+v, want one hit", view.SeenHosts[0])
	}

	if view.SeenHosts[0].FirstSeen == "" || view.SeenHosts[0].LastSeen == "" {
		t.Fatalf("seen host %+v has no times", view.SeenHosts[0])
	}

	if view.SeenLimitReached {
		t.Fatal("the limit was reported as reached on one host")
	}
}

// TestStartupDropsHostsThatBecameExceptions: хост, попавший в белый список после того, как
// его записали, уходит из таблицы при запуске службы, и журнал говорит, сколько записей
// убрано: иначе таблица обещала бы защиту, которой больше нет.
func TestStartupDropsHostsThatBecameExceptions(t *testing.T) {
	t.Parallel()

	path := filepath.Join(t.TempDir(), "hosts.tsv")
	recorded := "free.example.test\t2026-10-20T09:00:00Z\t2026-10-20T09:05:00Z\t12\n" +
		"watched.example.test\t2026-10-20T09:00:00Z\t2026-10-20T09:05:00Z\t3\n"

	err := os.WriteFile(path, []byte(recorded), 0o600)
	if err != nil {
		t.Fatalf("write table: %v", err)
	}

	table, journal := startProxyOverTable(t, path, []string{"free.example.test"})

	entries := table.Entries()
	if len(entries) != 1 || entries[0].Host != "watched.example.test" {
		t.Fatalf("seen hosts %+v, want only the guarded one", entries)
	}

	if !strings.Contains(journal.String(), "1 recorded hosts are exceptions now and were dropped") {
		t.Fatalf("journal does not tell about the dropped host:\n%s", journal.String())
	}

	content, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read table: %v", err)
	}

	if strings.Contains(string(content), "free.example.test") {
		t.Fatalf("the exception stayed in the file:\n%s", content)
	}
}

// startProxyOverTable поднимает прокси над лежащим файлом таблицы и отдаёт её и журнал.
func startProxyOverTable(t *testing.T, path string, unguarded []string) (*seen.Store, *lockedBuffer) {
	t.Helper()

	table, err := seen.Open(seen.Config{
		Path:  path,
		Limit: seen.DefaultLimit,
		Flush: seen.DefaultFlush,
		Now:   time.Now,
		Logf:  func(string, ...any) {},
	})
	if err != nil {
		t.Fatalf("open seen hosts: %v", err)
	}

	t.Cleanup(func() { _ = table.Close() })

	journal := &lockedBuffer{mutex: sync.Mutex{}, builder: strings.Builder{}}

	server, err := proxy.New(proxy.Config{
		Addr:           "127.0.0.1:0",
		Secret:         testSecret,
		UpstreamProxy:  "",
		ExpectedIP:     testIP,
		CheckURL:       testURL,
		UnguardedHosts: unguarded,
		Budget:         time.Minute,
		Checker:        okChecker(),
		Journal:        proxy.NewJournal(journal),
		Seen:           table,
	})
	if err != nil {
		t.Fatalf("new proxy: %v", err)
	}

	t.Cleanup(func() { _ = server.Close() })

	return table, journal
}

// TestProxyRequiresSeenTable: без таблицы прокси не поднимается — иначе встреченные хосты
// тихо копились бы в никуда.
func TestProxyRequiresSeenTable(t *testing.T) {
	t.Parallel()

	_, err := proxy.New(proxy.Config{
		Addr:           "127.0.0.1:0",
		Secret:         testSecret,
		UpstreamProxy:  "",
		ExpectedIP:     testIP,
		CheckURL:       testURL,
		UnguardedHosts: nil,
		Budget:         time.Minute,
		Checker:        okChecker(),
		Journal:        proxy.NewJournal(nil),
		Seen:           nil,
	})
	if err == nil {
		t.Fatal("the proxy started without a seen hosts table")
	}

	if !strings.Contains(err.Error(), "seen hosts") {
		t.Fatalf("refusal %q does not name the table", err)
	}
}

// checkOrder сверяет список с ожидаемым порядком.
func checkOrder(t *testing.T, got, want []string) {
	t.Helper()

	if len(got) != len(want) {
		t.Fatalf("unguarded hosts %v, want %v", got, want)
	}

	for index, pattern := range want {
		if got[index] != pattern {
			t.Fatalf("unguarded hosts %v, want %v in that order", got, want)
		}
	}
}

// mismatchChecker — вердикт «внешний IP не тот».
func mismatchChecker() stubChecker {
	return stubChecker{
		verdict: guard.Verdict{Kind: guard.KindMismatch, IP: testOtherIP, LastError: "", At: time.Now()},
	}
}

// closeConnect посылает CONNECT и сразу закрывает соединение: нужен сам факт обращения.
func closeConnect(t *testing.T, proxyAddr, target string) {
	t.Helper()

	connection, _, response := rawConnect(t, proxyAddr, target, basicHeader(testSecret))

	_ = response.Body.Close()
	_ = connection.Close()
}

// askStatus спрашивает `/status` и разбирает ответ.
func askStatus(t *testing.T, proxyAddr string) proxy.StatusView {
	t.Helper()

	request, err := http.NewRequestWithContext(
		context.Background(), http.MethodGet, "http://"+proxyAddr+"/status", http.NoBody,
	)
	if err != nil {
		t.Fatalf("status request: %v", err)
	}

	request.Header.Set("Authorization", basicHeader(testSecret))

	response, err := http.DefaultClient.Do(request)
	if err != nil {
		t.Fatalf("status: %v", err)
	}

	defer func() { _ = response.Body.Close() }()

	view := proxy.StatusView{} //nolint:exhaustruct // заполняется разбором ответа

	err = json.NewDecoder(response.Body).Decode(&view)
	if err != nil {
		t.Fatalf("decode status: %v", err)
	}

	return view
}
