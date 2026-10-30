package proxy_test

import (
	"bufio"
	"context"
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/kerbyfc/ipguard/internal/config"
	"github.com/kerbyfc/ipguard/internal/guard"
	"github.com/kerbyfc/ipguard/internal/proxy"
	"github.com/kerbyfc/ipguard/internal/seen"
)

const (
	testIP      = "203.0.113.7"
	testOtherIP = "198.51.100.4"
	testURL     = "https://icanhazip.test/"
	testSecret  = "proxy-secret"
	testBody    = "hello through the tunnel"
)

// stubChecker — вердикт без сети.
type stubChecker struct {
	verdict guard.Verdict
}

func (stub stubChecker) Verdict(_ context.Context) (guard.Verdict, error) {
	return stub.verdict, nil
}

// countingChecker считает обращения к вердикту.
type countingChecker struct {
	calls atomic.Int64
}

// lockedBuffer — журнал теста: прокси пишет в него из горутин соединений.
type lockedBuffer struct {
	mutex   sync.Mutex
	builder strings.Builder
}

func (buffer *lockedBuffer) Write(line []byte) (int, error) {
	buffer.mutex.Lock()
	defer buffer.mutex.Unlock()

	written, err := buffer.builder.Write(line)
	if err != nil {
		return written, fmt.Errorf("write test journal: %w", err)
	}

	return written, nil
}

func (buffer *lockedBuffer) String() string {
	buffer.mutex.Lock()
	defer buffer.mutex.Unlock()

	return buffer.builder.String()
}

func (checker *countingChecker) Verdict(_ context.Context) (guard.Verdict, error) {
	checker.calls.Add(1)

	return guard.Verdict{Kind: guard.KindOK, IP: testIP, LastError: "", At: time.Now()}, nil
}

func TestConnectPassesWhenIPMatches(t *testing.T) {
	t.Parallel()

	target := httptest.NewTLSServer(http.HandlerFunc(func(writer http.ResponseWriter, _ *http.Request) {
		_, _ = writer.Write([]byte(testBody))
	}))
	t.Cleanup(target.Close)

	server := startProxy(t, okChecker())

	status, body := throughProxy(t, server.Addr(), target.URL)
	if status != http.StatusOK || body != testBody {
		t.Fatalf("status %d body %q, want 200 and %q", status, body, testBody)
	}
}

func TestConnectBlockedOnMismatch(t *testing.T) {
	t.Parallel()

	server := startProxy(t, stubChecker{
		verdict: guard.Verdict{
			Kind:      guard.KindMismatch,
			IP:        testOtherIP,
			LastError: "",
			At:        time.Now(),
		},
	})

	connection, _, response := rawConnect(t, server.Addr(), "example.test:443", basicHeader(testSecret))

	defer func() { _ = response.Body.Close() }()
	defer func() { _ = connection.Close() }()

	if response.StatusCode != http.StatusForbidden {
		t.Fatalf("status %d, want 403", response.StatusCode)
	}

	body, err := io.ReadAll(response.Body)
	if err != nil {
		t.Fatalf("read body: %v", err)
	}

	want := "claude-ipguard: blocked: external IP is '" + testOtherIP + "', expected " + testIP
	if !strings.Contains(string(body), want) {
		t.Fatalf("body %q does not carry the reason %q", body, want)
	}
}

func TestConnectWithoutSecret(t *testing.T) {
	t.Parallel()

	server := startProxy(t, okChecker())

	connection, _, response := rawConnect(t, server.Addr(), "example.test:443", "")

	defer func() { _ = response.Body.Close() }()
	defer func() { _ = connection.Close() }()

	if response.StatusCode != http.StatusProxyAuthRequired {
		t.Fatalf("status %d without a secret, want 407", response.StatusCode)
	}

	if !strings.HasPrefix(response.Header.Get("Proxy-Authenticate"), "Basic ") {
		t.Fatalf("Proxy-Authenticate %q, want a Basic challenge", response.Header.Get("Proxy-Authenticate"))
	}
}

func TestConnectWithWrongSecret(t *testing.T) {
	t.Parallel()

	server := startProxy(t, okChecker())

	connection, _, response := rawConnect(t, server.Addr(), "example.test:443", basicHeader("wrong-secret"))

	defer func() { _ = response.Body.Close() }()
	defer func() { _ = connection.Close() }()

	if response.StatusCode != http.StatusProxyAuthRequired {
		t.Fatalf("status %d with a wrong secret, want 407", response.StatusCode)
	}
}

// TestTunnelSurvivesSlowStream: ответ, идущий с паузами, не обрывается — у туннеля нет
// таймаута простоя, иначе длинный ответ модели рвался бы на середине.
func TestTunnelSurvivesSlowStream(t *testing.T) {
	t.Parallel()

	const (
		chunks = 3
		pause  = 700 * time.Millisecond
	)

	var listenConfig net.ListenConfig

	listener, err := listenConfig.Listen(context.Background(), "tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}

	t.Cleanup(func() { _ = listener.Close() })

	go func() {
		connection, acceptErr := listener.Accept()
		if acceptErr != nil {
			return
		}

		defer func() { _ = connection.Close() }()

		for range chunks {
			time.Sleep(pause)

			_, writeErr := connection.Write([]byte(testBody))
			if writeErr != nil {
				return
			}
		}
	}()

	server := startProxy(t, okChecker())

	connection, reader, response := rawConnect(t, server.Addr(), listener.Addr().String(), basicHeader(testSecret))

	defer func() { _ = response.Body.Close() }()
	defer func() { _ = connection.Close() }()

	if response.StatusCode != http.StatusOK {
		t.Fatalf("status %d, want 200 Connection Established", response.StatusCode)
	}

	stream, err := io.ReadAll(reader)
	if err != nil {
		t.Fatalf("read the stream: %v", err)
	}

	want := strings.Repeat(testBody, chunks)
	if string(stream) != want {
		t.Fatalf("stream %q, want %q", stream, want)
	}
}

func TestStatusShowsVerdict(t *testing.T) {
	t.Parallel()

	checked := time.Now().Add(-time.Minute)
	server := startProxy(t, stubChecker{
		verdict: guard.Verdict{
			Kind:      guard.KindBudget,
			IP:        "",
			LastError: "dial tcp: no network",
			At:        checked,
		},
	})

	request, err := http.NewRequestWithContext(
		context.Background(), http.MethodGet, "http://"+server.Addr()+"/status", http.NoBody,
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

	if response.StatusCode != http.StatusOK {
		t.Fatalf("status code %d, want 200", response.StatusCode)
	}

	var view proxy.StatusView

	err = json.NewDecoder(response.Body).Decode(&view)
	if err != nil {
		t.Fatalf("decode status: %v", err)
	}

	if view.Verdict != string(guard.KindBudget) || view.Allowed {
		t.Fatalf("status verdict %q allowed=%v, want budget and denied", view.Verdict, view.Allowed)
	}

	if view.LastError != "dial tcp: no network" {
		t.Fatalf("status last error %q", view.LastError)
	}

	if view.CheckedAt != checked.Format(time.RFC3339) {
		t.Fatalf("status checked at %q, want %q", view.CheckedAt, checked.Format(time.RFC3339))
	}

	if !strings.Contains(view.Message, "failed within 540 s") {
		t.Fatalf("status message %q is not the contract wording", view.Message)
	}
}

// TestStatusRequestsFreshVerdict: `/status` — такой же подписчик обещания, как соединение:
// вердикт нигде не хранится, поэтому каждое обращение спрашивает проверку заново.
func TestStatusRequestsFreshVerdict(t *testing.T) {
	t.Parallel()

	checker := &countingChecker{calls: atomic.Int64{}}
	server := startProxy(t, checker)

	for index := range 2 {
		request, err := http.NewRequestWithContext(
			context.Background(), http.MethodGet, "http://"+server.Addr()+"/status", http.NoBody,
		)
		if err != nil {
			t.Fatalf("status request %d: %v", index, err)
		}

		request.Header.Set("Authorization", basicHeader(testSecret))

		response, err := http.DefaultClient.Do(request)
		if err != nil {
			t.Fatalf("status %d: %v", index, err)
		}

		_ = response.Body.Close()

		if response.StatusCode != http.StatusOK {
			t.Fatalf("status %d code %d, want 200", index, response.StatusCode)
		}
	}

	if checker.calls.Load() != 2 {
		t.Fatalf("status requests caused %d checks, want 2: each request asks the checker anew", checker.calls.Load())
	}
}

func TestStatusWithoutSecret(t *testing.T) {
	t.Parallel()

	server := startProxy(t, okChecker())

	request, err := http.NewRequestWithContext(
		context.Background(), http.MethodGet, "http://"+server.Addr()+"/status", http.NoBody,
	)
	if err != nil {
		t.Fatalf("status request: %v", err)
	}

	response, err := http.DefaultClient.Do(request)
	if err != nil {
		t.Fatalf("status: %v", err)
	}

	defer func() { _ = response.Body.Close() }()

	if response.StatusCode != http.StatusProxyAuthRequired {
		t.Fatalf("status code %d without a secret, want 407", response.StatusCode)
	}
}

func TestPlainRequestForwarded(t *testing.T) {
	t.Parallel()

	target := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, _ *http.Request) {
		_, _ = writer.Write([]byte(testBody))
	}))
	t.Cleanup(target.Close)

	server := startProxy(t, okChecker())

	status, body := throughProxy(t, server.Addr(), target.URL)
	if status != http.StatusOK || body != testBody {
		t.Fatalf("status %d body %q, want 200 and %q", status, body, testBody)
	}
}

func TestPlainRequestBlockedOnMismatch(t *testing.T) {
	t.Parallel()

	server := startProxy(t, stubChecker{
		verdict: guard.Verdict{
			Kind:      guard.KindMismatch,
			IP:        testOtherIP,
			LastError: "",
			At:        time.Now(),
		},
	})

	status, body := throughProxy(t, server.Addr(), "http://example.test/")
	if status != http.StatusForbidden {
		t.Fatalf("status %d, want 403", status)
	}

	if !strings.Contains(body, "external IP is '"+testOtherIP+"'") {
		t.Fatalf("body %q does not carry the reason", body)
	}
}

// TestUnguardedHostPassesWithoutCheckAndLogsOnce: локальная цель идёт сразу, проверка IP не
// вызывается, а строка журнала про хост вне охраны пишется один раз, не на каждое соединение.
func TestUnguardedHostPassesWithoutCheckAndLogsOnce(t *testing.T) {
	t.Parallel()

	checker := &countingChecker{calls: atomic.Int64{}}
	server, journal := startProxyWithJournal(t, checker, "", nil)

	for attempt := range 2 {
		connection, _, response := rawConnect(
			t, server.Addr(), "127.0.0.1:1", basicHeader(testSecret),
		)
		_ = response.Body.Close()
		_ = connection.Close()

		if response.StatusCode == http.StatusForbidden {
			t.Fatalf("attempt %d: unguarded host was blocked", attempt+1)
		}
	}

	if checker.calls.Load() != 0 {
		t.Fatalf("un guarded host caused %d checks, want 0", checker.calls.Load())
	}

	if lines := strings.Count(journal.String(), "host outside guard: 127.0.0.1"); lines != 1 {
		t.Fatalf("journal has %d lines about the unguarded host, want 1:\n%s", lines, journal.String())
	}
}

// TestCheckURLHostIsNeverGuarded: источник проверки не охраняется, хотя под вердиктом теперь
// любой хост: иначе проверка ждала бы собственного вердикта.
func TestCheckURLHostIsNeverGuarded(t *testing.T) {
	t.Parallel()

	checker := &countingChecker{calls: atomic.Int64{}}
	server := startProxyWithUnguarded(t, checker, "", nil)

	connection, _, response := rawConnect(t, server.Addr(), "icanhazip.test:1", basicHeader(testSecret))

	defer func() { _ = response.Body.Close() }()
	defer func() { _ = connection.Close() }()

	if response.StatusCode == http.StatusForbidden {
		t.Fatal("the check host was blocked by its own guard")
	}

	if checker.calls.Load() != 0 {
		t.Fatalf("the check host caused %d checks, want 0", checker.calls.Load())
	}
}

func okChecker() stubChecker {
	return stubChecker{
		verdict: guard.Verdict{Kind: guard.KindOK, IP: testIP, LastError: "", At: time.Now()},
	}
}

func basicHeader(secret string) string {
	return "Basic " + base64.StdEncoding.EncodeToString([]byte("claude:"+secret))
}

func startProxy(t *testing.T, checker proxy.Verdicter) *proxy.Server {
	t.Helper()

	return startProxyWithUpstream(t, checker, "")
}

// startProxyWithUpstream поднимает прокси на свободном порту loopback, с верхним прокси или без.
func startProxyWithUpstream(t *testing.T, checker proxy.Verdicter, upstream string) *proxy.Server {
	t.Helper()

	return startProxyWithUnguarded(t, checker, upstream, nil)
}

// startProxyWithUnguarded поднимает прокси с заданным белым списком.
func startProxyWithUnguarded(
	t *testing.T, checker proxy.Verdicter, upstream string, unguarded []string,
) *proxy.Server {
	t.Helper()

	server, _ := startProxyWithJournal(t, checker, upstream, unguarded)

	return server
}

// startProxyWithJournal поднимает прокси и отдаёт его журнал: по нему видно, что попало в
// строки, а что нет.
func startProxyWithJournal(
	t *testing.T, checker proxy.Verdicter, upstream string, unguarded []string,
) (*proxy.Server, *lockedBuffer) {
	t.Helper()

	server, journal, _ := startProxyWithSeen(t, checker, upstream, unguarded)

	return server, journal
}

// startProxyWithSeen поднимает прокси и отдаёт заодно таблицу встреченных хостов.
func startProxyWithSeen(
	t *testing.T, checker proxy.Verdicter, upstream string, unguarded []string,
) (*proxy.Server, *lockedBuffer, *seen.Store) {
	t.Helper()

	journal := &lockedBuffer{mutex: sync.Mutex{}, builder: strings.Builder{}}
	table := testSeen(t)

	server, err := proxy.New(proxy.Config{
		Addr:           "127.0.0.1:0",
		Secret:         testSecret,
		UpstreamProxy:  upstream,
		ExpectedIP:     testIP,
		CheckURL:       testURL,
		UnguardedHosts: unguarded,
		Budget:         config.DefaultBudget,
		Checker:        checker,
		Journal:        proxy.NewJournal(journal),
		Seen:           table,
	})
	if err != nil {
		t.Fatalf("new proxy: %v", err)
	}

	var serving sync.WaitGroup

	serving.Add(1)

	go func() {
		defer serving.Done()

		serveErr := server.Serve()
		if serveErr != nil {
			t.Errorf("serve: %v", serveErr)
		}
	}()

	t.Cleanup(func() {
		_ = server.Close()

		serving.Wait()
	})

	return server, journal, table
}

// testSeen — таблица встреченных хостов теста: свой каталог, настоящие часы.
func testSeen(t *testing.T) *seen.Store {
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

	return table
}

// throughProxy делает запрос через наш прокси и отдаёт статус и тело ответа.
func throughProxy(t *testing.T, proxyAddr, target string) (int, string) {
	t.Helper()

	client := proxyClient(t, proxyAddr)

	request, err := http.NewRequestWithContext(context.Background(), http.MethodGet, target, http.NoBody)
	if err != nil {
		t.Fatalf("request: %v", err)
	}

	response, err := client.Do(request)
	if err != nil {
		t.Fatalf("request through the proxy: %v", err)
	}

	defer func() { _ = response.Body.Close() }()

	body, err := io.ReadAll(response.Body)
	if err != nil {
		t.Fatalf("read body: %v", err)
	}

	return response.StatusCode, string(body)
}

// proxyClient — клиент, ходящий через наш прокси с секретом в адресе прокси, как это делает
// claude по HTTPS_PROXY.
func proxyClient(t *testing.T, addr string) *http.Client {
	t.Helper()

	proxyURL, err := url.Parse("http://claude:" + testSecret + "@" + addr)
	if err != nil {
		t.Fatalf("proxy url: %v", err)
	}

	//nolint:exhaustruct,gosec // задано доверие к самодельному сертификату httptest
	tlsConfig := &tls.Config{InsecureSkipVerify: true, MinVersion: tls.VersionTLS12}

	//nolint:exhaustruct // заданы прокси и доверие к сертификату тестового сервера
	transport := &http.Transport{
		Proxy:           http.ProxyURL(proxyURL),
		TLSClientConfig: tlsConfig,
	}

	t.Cleanup(transport.CloseIdleConnections)

	//nolint:exhaustruct // задан транспорт, остальное — значения по умолчанию
	return &http.Client{Transport: transport}
}

// rawConnect посылает CONNECT руками: так видно статус и тело отказа, которые http.Client
// прячет за ошибкой соединения.
func rawConnect(t *testing.T, proxyAddr, target, auth string) (net.Conn, *bufio.Reader, *http.Response) {
	t.Helper()

	var dialer net.Dialer

	connection, err := dialer.DialContext(context.Background(), "tcp", proxyAddr)
	if err != nil {
		t.Fatalf("dial proxy: %v", err)
	}

	request := "CONNECT " + target + " HTTP/1.1\r\nHost: " + target + "\r\n"
	if auth != "" {
		request += "Proxy-Authorization: " + auth + "\r\n"
	}

	_, err = connection.Write([]byte(request + "\r\n"))
	if err != nil {
		t.Fatalf("write CONNECT: %v", err)
	}

	reader := bufio.NewReader(connection)

	//nolint:exhaustruct // ReadResponse нужен только метод запроса
	response, err := http.ReadResponse(reader, &http.Request{Method: http.MethodConnect})
	if err != nil {
		t.Fatalf("read CONNECT response: %v", err)
	}

	return connection, reader, response
}
