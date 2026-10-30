package proxy

import (
	"net/http"
	"testing"
)

// TestStripHopHeaders: убираются и постоянный список, и заголовки, названные в `Connection`.
func TestStripHopHeaders(t *testing.T) {
	t.Parallel()

	header := http.Header{}
	header.Set("Connection", "X-Custom, Upgrade")
	header.Add("Connection", "X-Second")
	header.Set("X-Custom", "one")
	header.Set("X-Second", "two")
	header.Set("Proxy-Authorization", "Basic cccc")
	header.Set("Keep-Alive", "timeout=5")
	header.Set("X-Kept", "stays")

	stripHopHeaders(header)

	for _, name := range []string{"Connection", "X-Custom", "X-Second", "Proxy-Authorization", "Keep-Alive"} {
		if header.Get(name) != "" {
			t.Fatalf("header %s survived: %q", name, header.Get(name))
		}
	}

	if header.Get("X-Kept") != "stays" {
		t.Fatalf("header X-Kept is %q, want stays", header.Get("X-Kept"))
	}
}
