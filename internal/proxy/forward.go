package proxy

import (
	"io"
	"net/http"
	"strings"
)

// hopHeaders — заголовки одного участка пути: дальше они не передаются.
var hopHeaders = []string{
	"Connection",
	"Proxy-Connection",
	proxyAuthHeader,
	"Proxy-Authenticate",
	"Keep-Alive",
	"Te",
	"Trailer",
	"Transfer-Encoding",
	"Upgrade",
}

// forward проксирует обычный HTTP-запрос с абсолютным URL.
func (server *Server) forward(writer http.ResponseWriter, request *http.Request) {
	if !server.permit(writer, request) {
		return
	}

	outbound := request.Clone(request.Context())
	outbound.RequestURI = ""
	outbound.Close = false
	stripHopHeaders(outbound.Header)

	response, err := server.transport.RoundTrip(outbound)
	if err != nil {
		server.config.Journal.Printf("forward %s failed: %v", requestTarget(request), err)
		http.Error(writer, "claude-ipguard: forward failed: "+err.Error(), http.StatusBadGateway)

		return
	}

	defer func() { _ = response.Body.Close() }()

	stripHopHeaders(response.Header)

	for name, values := range response.Header {
		for _, value := range values {
			writer.Header().Add(name, value)
		}
	}

	writer.WriteHeader(response.StatusCode)

	_, err = io.Copy(writer, response.Body)
	if err != nil {
		server.config.Journal.Printf("forward %s body stopped: %v", requestTarget(request), err)
	}
}

// stripHopHeaders убирает заголовки одного участка пути: и постоянный список, и те, что
// названы в самом `Connection` (RFC 7230 §6.1) — иначе `Connection: X-Custom` пропускал бы
// `X-Custom` дальше по пути.
func stripHopHeaders(header http.Header) {
	for _, value := range header.Values("Connection") {
		for _, name := range strings.Split(value, ",") {
			name = strings.TrimSpace(name)
			if name != "" {
				header.Del(name)
			}
		}
	}

	for _, name := range hopHeaders {
		header.Del(name)
	}
}
