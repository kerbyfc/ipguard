package proxy

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"sync"
	"time"
)

const (
	connectEstablished = "HTTP/1.1 200 Connection Established\r\n\r\n"
	tunnelDialTimeout  = 30 * time.Second
)

// closeWriter — половинное закрытие: сторона, у которой кончился поток, закрывает только
// свою запись, и обратное направление доживает до конца.
type closeWriter interface {
	CloseWrite() error
}

// tunnel проводит CONNECT без расшифровки: TLS не вскрывается, байты идут как есть.
func (server *Server) tunnel(writer http.ResponseWriter, request *http.Request) {
	if !server.permit(writer, request) {
		return
	}

	target := request.Host

	upstream, err := server.dialTunnel(request.Context(), target)
	if err != nil {
		server.config.Journal.Printf("tunnel to %s failed: %v", target, err)
		http.Error(writer, "claude-ipguard: tunnel failed: "+err.Error(), http.StatusBadGateway)

		return
	}

	hijacker, ok := writer.(http.Hijacker)
	if !ok {
		_ = upstream.Close()

		http.Error(writer, "claude-ipguard: connection hijack is unsupported", http.StatusInternalServerError)

		return
	}

	client, buffered, err := hijacker.Hijack()
	if err != nil {
		_ = upstream.Close()

		server.config.Journal.Printf("tunnel to %s failed: hijack: %v", target, err)

		return
	}

	_, err = buffered.WriteString(connectEstablished)
	if err == nil {
		err = buffered.Flush()
	}

	if err != nil {
		_ = upstream.Close()
		_ = client.Close()

		server.config.Journal.Printf("tunnel to %s failed: %v", target, err)

		return
	}

	// Сроков на туннеле нет ни с одной стороны: ответы модели идут длинным потоком с
	// паузами, и таймаут простоя порвал бы живой ответ.
	_ = client.SetDeadline(time.Time{})
	_ = upstream.SetDeadline(time.Time{})

	server.relay(client, buffered, upstream)
}

// relay перекладывает байты в обе стороны до закрытия пиром.
func (server *Server) relay(client net.Conn, buffered *bufio.ReadWriter, upstream net.Conn) {
	defer func() {
		_ = upstream.Close()
		_ = client.Close()
	}()

	var both sync.WaitGroup

	both.Add(2)

	go func() {
		defer both.Done()

		server.pipe(upstream, buffered)
	}()

	go func() {
		defer both.Done()

		server.pipe(client, upstream)
	}()

	both.Wait()
}

// pipe копирует из src в dst и закрывает запись в dst, когда поток кончился.
func (server *Server) pipe(dst net.Conn, src io.Reader) {
	_, err := io.Copy(dst, src)
	if err != nil {
		server.config.Journal.Printf("tunnel copy to %s stopped: %v", dst.RemoteAddr(), err)
	}

	half, ok := dst.(closeWriter)
	if !ok {
		_ = dst.Close()

		return
	}

	_ = half.CloseWrite()
}

// dialTunnel соединяется с целью: напрямую или CONNECT через верхний прокси.
func (server *Server) dialTunnel(ctx context.Context, target string) (net.Conn, error) {
	dialCtx, cancel := context.WithTimeout(ctx, tunnelDialTimeout)
	defer cancel()

	if server.config.UpstreamProxy == "" {
		connection, err := server.dialer.DialContext(dialCtx, "tcp", target)
		if err != nil {
			return nil, fmt.Errorf("%w: dial %s: %w", ErrServer, target, err)
		}

		return connection, nil
	}

	return server.dialThroughUpstream(dialCtx, target)
}

// dialThroughUpstream просит верхний прокси открыть туннель к цели.
func (server *Server) dialThroughUpstream(ctx context.Context, target string) (net.Conn, error) {
	parsed, err := url.Parse(server.config.UpstreamProxy)
	if err != nil {
		return nil, fmt.Errorf("%w: upstream proxy %q: %w", ErrServer, server.config.UpstreamProxy, err)
	}

	address := parsed.Host
	if parsed.Port() == "" {
		address = net.JoinHostPort(parsed.Hostname(), "80")
	}

	connection, err := server.dialer.DialContext(ctx, "tcp", address)
	if err != nil {
		return nil, fmt.Errorf("%w: dial upstream proxy %s: %w", ErrServer, address, err)
	}

	err = writeUpstreamConnect(connection, parsed, target)
	if err != nil {
		_ = connection.Close()

		return nil, err
	}

	reader := bufio.NewReader(connection)

	//nolint:exhaustruct // ReadResponse нужен только метод запроса
	connectRequest := &http.Request{Method: http.MethodConnect}

	response, err := http.ReadResponse(reader, connectRequest)
	if err != nil {
		_ = connection.Close()

		return nil, fmt.Errorf("%w: upstream proxy response: %w", ErrServer, err)
	}

	defer func() { _ = response.Body.Close() }()

	if response.StatusCode != http.StatusOK {
		_ = connection.Close()

		return nil, fmt.Errorf("%w: upstream proxy answered %s", ErrServer, response.Status)
	}

	if reader.Buffered() > 0 {
		_ = connection.Close()

		return nil, fmt.Errorf("%w: upstream proxy sent %d bytes before the tunnel", ErrServer, reader.Buffered())
	}

	return connection, nil
}

// writeUpstreamConnect пишет CONNECT верхнему прокси, с его собственной авторизацией, если
// она задана в адресе.
func writeUpstreamConnect(connection net.Conn, proxyURL *url.URL, target string) error {
	request := "CONNECT " + target + " HTTP/1.1\r\nHost: " + target + "\r\n"

	password, hasPassword := proxyURL.User.Password()
	if hasPassword {
		credentials := proxyURL.User.Username() + ":" + password
		request += proxyAuthHeader + ": " + basicPrefix + basicEncode(credentials) + "\r\n"
	}

	_, err := connection.Write([]byte(request + "\r\n"))
	if err != nil {
		return fmt.Errorf("%w: upstream proxy CONNECT: %w", ErrServer, err)
	}

	return nil
}
