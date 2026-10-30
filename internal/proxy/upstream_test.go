package proxy_test

import (
	"encoding/base64"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
)

const upstreamSecret = "upstream-secret"

// upstreamStub — подставной верхний прокси: туннелирует CONNECT к цели и запоминает, что
// видел, включая свою авторизацию.
type upstreamStub struct {
	mutex    sync.Mutex
	connects []string
	plain    []string
	auth     []string
}

func (stub *upstreamStub) ServeHTTP(writer http.ResponseWriter, request *http.Request) {
	stub.mutex.Lock()
	stub.auth = append(stub.auth, request.Header.Get("Proxy-Authorization"))

	if request.Method == http.MethodConnect {
		stub.connects = append(stub.connects, request.Host)
	} else {
		stub.plain = append(stub.plain, request.URL.String())
	}

	stub.mutex.Unlock()

	if request.Method != http.MethodConnect {
		_, _ = writer.Write([]byte(testBody))

		return
	}

	stub.tunnel(writer, request)
}

// tunnel открывает туннель к цели: ровно то, что делает настоящий верхний прокси.
func (stub *upstreamStub) tunnel(writer http.ResponseWriter, request *http.Request) {
	var dialer net.Dialer

	target, err := dialer.DialContext(request.Context(), "tcp", request.Host)
	if err != nil {
		http.Error(writer, "upstream dial failed", http.StatusBadGateway)

		return
	}

	hijacker, ok := writer.(http.Hijacker)
	if !ok {
		_ = target.Close()

		http.Error(writer, "hijack unsupported", http.StatusInternalServerError)

		return
	}

	client, buffered, err := hijacker.Hijack()
	if err != nil {
		_ = target.Close()

		return
	}

	_, err = buffered.WriteString("HTTP/1.1 200 Connection Established\r\n\r\n")
	if err == nil {
		err = buffered.Flush()
	}

	if err != nil {
		_ = target.Close()
		_ = client.Close()

		return
	}

	go func() {
		_, _ = io.Copy(target, buffered)
		_ = target.Close()
	}()

	go func() {
		_, _ = io.Copy(client, target)
		_ = client.Close()
	}()
}

func (stub *upstreamStub) seen() ([]string, []string, []string) {
	stub.mutex.Lock()
	defer stub.mutex.Unlock()

	return append([]string(nil), stub.connects...),
		append([]string(nil), stub.plain...),
		append([]string(nil), stub.auth...)
}

// TestConnectThroughUpstreamProxy: при заданном верхнем прокси туннель идёт через него, с его
// авторизацией из адреса.
func TestConnectThroughUpstreamProxy(t *testing.T) {
	t.Parallel()

	stub := &upstreamStub{mutex: sync.Mutex{}, connects: nil, plain: nil, auth: nil}
	upstream := httptest.NewServer(stub)
	t.Cleanup(upstream.Close)

	target := httptest.NewTLSServer(http.HandlerFunc(func(writer http.ResponseWriter, _ *http.Request) {
		_, _ = writer.Write([]byte(testBody))
	}))
	t.Cleanup(target.Close)

	server := startProxyWithUpstream(t, okChecker(), withCredentials(upstream.URL))

	status, body := throughProxy(t, server.Addr(), target.URL)
	if status != http.StatusOK || body != testBody {
		t.Fatalf("status %d body %q, want 200 and %q", status, body, testBody)
	}

	connects, _, auth := stub.seen()

	targetHost := strings.TrimPrefix(target.URL, "https://")
	if len(connects) != 1 || connects[0] != targetHost {
		t.Fatalf("upstream proxy saw CONNECT %v, want [%s]", connects, targetHost)
	}

	want := "Basic " + base64.StdEncoding.EncodeToString([]byte("up:"+upstreamSecret))
	if len(auth) != 1 || auth[0] != want {
		t.Fatalf("upstream proxy saw authorization %v, want [%s] from its URL", auth, want)
	}
}

// TestPlainRequestThroughUpstreamProxy: обычный HTTP-запрос тоже идёт через верхний прокси.
func TestPlainRequestThroughUpstreamProxy(t *testing.T) {
	t.Parallel()

	stub := &upstreamStub{mutex: sync.Mutex{}, connects: nil, plain: nil, auth: nil}
	upstream := httptest.NewServer(stub)
	t.Cleanup(upstream.Close)

	server := startProxyWithUpstream(t, okChecker(), upstream.URL)

	status, body := throughProxy(t, server.Addr(), "http://example.test/ip")
	if status != http.StatusOK || body != testBody {
		t.Fatalf("status %d body %q, want 200 and %q", status, body, testBody)
	}

	_, plain, _ := stub.seen()
	if len(plain) != 1 || plain[0] != "http://example.test/ip" {
		t.Fatalf("upstream proxy saw %v, want [http://example.test/ip]", plain)
	}
}

// TestUpstreamProxyRefusalIsVisible: верхний прокси отказал — 502, а не тихий прямой выход.
func TestUpstreamProxyRefusalIsVisible(t *testing.T) {
	t.Parallel()

	upstream := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, _ *http.Request) {
		http.Error(writer, "no tunnels here", http.StatusForbidden)
	}))
	t.Cleanup(upstream.Close)

	server := startProxyWithUpstream(t, okChecker(), upstream.URL)

	connection, _, response := rawConnect(t, server.Addr(), "example.test:443", basicHeader(testSecret))

	defer func() { _ = response.Body.Close() }()
	defer func() { _ = connection.Close() }()

	if response.StatusCode != http.StatusBadGateway {
		t.Fatalf("status %d, want 502", response.StatusCode)
	}

	body, err := io.ReadAll(response.Body)
	if err != nil {
		t.Fatalf("read body: %v", err)
	}

	if !strings.Contains(string(body), "upstream proxy answered") {
		t.Fatalf("body %q does not name the upstream refusal", body)
	}
}

// withCredentials вписывает в адрес верхнего прокси его собственную авторизацию.
func withCredentials(address string) string {
	return "http://up:" + upstreamSecret + "@" + strings.TrimPrefix(address, "http://")
}
