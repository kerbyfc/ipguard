package guard_test

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/kerbyfc/ipguard/internal/guard"
)

// TestFetchIPTrimsBody: ответ хоста проверки приходит с переводом строки и пробелами —
// вердикт сравнивает уже очищенное значение.
func TestFetchIPTrimsBody(t *testing.T) {
	t.Parallel()

	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, _ *http.Request) {
		_, _ = writer.Write([]byte("  " + testIP + " \n"))
	}))
	t.Cleanup(server.Close)

	body, err := guard.FetchIP(context.Background(), server.URL, "")
	if err != nil {
		t.Fatalf("fetch: %v", err)
	}

	if body != testIP {
		t.Fatalf("body %q, want %q", body, testIP)
	}
}

// TestFetchIPRejectsErrorStatus: не-2xx — ошибка, а не «тело пустое».
func TestFetchIPRejectsErrorStatus(t *testing.T) {
	t.Parallel()

	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, _ *http.Request) {
		http.Error(writer, "nope", http.StatusInternalServerError)
	}))
	t.Cleanup(server.Close)

	_, err := guard.FetchIP(context.Background(), server.URL, "")
	if !errors.Is(err, guard.ErrHTTPStatus) {
		t.Fatalf("error %v, want ErrHTTPStatus", err)
	}
}

// TestFetchIPRejectsNotModified: 304 тоже не ответ хоста проверки.
func TestFetchIPRejectsNotModified(t *testing.T) {
	t.Parallel()

	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, _ *http.Request) {
		writer.WriteHeader(http.StatusNotModified)
	}))
	t.Cleanup(server.Close)

	_, err := guard.FetchIP(context.Background(), server.URL, "")
	if !errors.Is(err, guard.ErrHTTPStatus) {
		t.Fatalf("error %v, want ErrHTTPStatus", err)
	}
}

// TestFetchIPRefusesRedirect: по редиректу сторож не идёт — тело с чужого адреса он принял бы
// за внешний IP.
func TestFetchIPRefusesRedirect(t *testing.T) {
	t.Parallel()

	target := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, _ *http.Request) {
		_, _ = writer.Write([]byte("203.0.113.9"))
	}))
	t.Cleanup(target.Close)

	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		http.Redirect(writer, request, target.URL, http.StatusFound)
	}))
	t.Cleanup(server.Close)

	ip, err := guard.FetchIP(context.Background(), server.URL, "")
	if !errors.Is(err, guard.ErrHTTPStatus) {
		t.Fatalf("error %v, want ErrHTTPStatus", err)
	}

	if ip != "" {
		t.Fatalf("ip %q, want empty", ip)
	}
}

// TestFetchIPReportsNetworkFailure: сеть не ответила — ошибка запроса.
func TestFetchIPReportsNetworkFailure(t *testing.T) {
	t.Parallel()

	server := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	address := server.URL
	server.Close()

	_, err := guard.FetchIP(context.Background(), address, "")
	if !errors.Is(err, guard.ErrFetch) {
		t.Fatalf("error %v, want ErrFetch", err)
	}
}

// TestFetchIPRejectsBrokenProxy: негодный адрес верхнего прокси — ошибка настройки.
func TestFetchIPRejectsBrokenProxy(t *testing.T) {
	t.Parallel()

	_, err := guard.FetchIP(context.Background(), testURL, "http://%zz")
	if !errors.Is(err, guard.ErrProxy) {
		t.Fatalf("error %v, want ErrProxy", err)
	}
}

// TestFetchIPGoesThroughUpstreamProxy: при заданном верхнем прокси запрос идёт через него,
// а не напрямую.
func TestFetchIPGoesThroughUpstreamProxy(t *testing.T) {
	t.Parallel()

	seen := make(chan string, 1)

	upstream := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		seen <- request.URL.String()

		_, _ = writer.Write([]byte(testIP))
	}))
	t.Cleanup(upstream.Close)

	body, err := guard.FetchIP(context.Background(), "http://icanhazip.test/", upstream.URL)
	if err != nil {
		t.Fatalf("fetch through the upstream proxy: %v", err)
	}

	if body != testIP {
		t.Fatalf("body %q, want %q", body, testIP)
	}

	select {
	case target := <-seen:
		if target != "http://icanhazip.test/" {
			t.Fatalf("upstream proxy saw %q", target)
		}
	default:
		t.Fatal("upstream proxy saw no request")
	}
}
