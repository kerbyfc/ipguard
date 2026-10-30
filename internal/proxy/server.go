// Package proxy — локальный HTTP-прокси сторожа: CONNECT туннелируется без расшифровки TLS,
// обычный HTTP проксируется, и то и другое идёт только при вердикте «внешний IP совпал».
// Отказ по умолчанию закрытый: нет вердикта — нет соединения.
package proxy

import (
	"context"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"os"
	"runtime/debug"
	"strings"
	"sync"
	"time"

	"github.com/kerbyfc/ipguard/internal/guard"
	"github.com/kerbyfc/ipguard/internal/hosts"
	"github.com/kerbyfc/ipguard/internal/seen"
)

const (
	// exitPanic — код выхода при панике: сторож падает, а не продолжает пускать трафик.
	exitPanic = 70

	// readHeaderTimeout ограничивает чтение заголовков запроса. На установленный туннель он
	// не влияет: после Hijack дескриптор уходит из net/http без сроков.
	readHeaderTimeout = 10 * time.Second

	statusPath          = "/status"
	authRealm           = "claude-ipguard"
	proxyAuthHeader     = "Proxy-Authorization"
	requestAuthHeader   = "Authorization"
	basicPrefix         = "Basic "
	deniedAuthMessage   = "claude-ipguard: proxy secret is required"
	deniedBlockedPrefix = "claude-ipguard: blocked: "
)

// ErrServer — прокси не поднялся.
var ErrServer = errors.New("ipguard proxy failed")

// Verdicter — источник вердикта о внешнем IP.
type Verdicter interface {
	// Verdict отдаёт вердикт новой проверки или идущего обещания.
	Verdict(ctx context.Context) (guard.Verdict, error)
}

// Config — настройка прокси.
type Config struct {
	Addr          string
	Secret        string
	UpstreamProxy string
	ExpectedIP    string
	CheckURL      string
	// UnguardedHosts — шаблоны белого списка: хосты, которые идут мимо проверки. Хост
	// проверки и локальные цели исключены в коде и в списке не нужны.
	UnguardedHosts []string
	Budget         time.Duration
	Checker        Verdicter
	Journal        *Journal
	// Seen — таблица защищаемых хостов: по ней видно, что сторож держит под вердиктом.
	// Исключения в неё не попадают.
	Seen *seen.Store
}

// Server — слушатель прокси.
type Server struct {
	config    Config
	listener  net.Listener
	server    *http.Server
	transport *http.Transport
	dialer    *net.Dialer

	// exempt — шаблоны белого списка; checkHost — хост проверки, который охранять нельзя.
	exempt    *hosts.List
	checkHost string

	// told — исключения, о которых журнал уже сказал: строка на хост, а не на каждое
	// соединение. В таблицу защищаемых они не идут, поэтому помнит их сам слушатель.
	toldMutex sync.Mutex
	told      map[string]struct{}
	toldFull  bool
}

// Addr — адрес слушателя (порт 0 в настройках превращается в выданный системой).
func (server *Server) Addr() string {
	return server.listener.Addr().String()
}

// Serve обслуживает соединения до Close.
func (server *Server) Serve() error {
	server.config.Journal.Printf("ipguard proxy listening on %s", server.Addr())

	err := server.server.Serve(server.listener)
	if err != nil && !errors.Is(err, http.ErrServerClosed) {
		return fmt.Errorf("%w: %w", ErrServer, err)
	}

	return nil
}

// Close останавливает слушателя.
func (server *Server) Close() error {
	err := server.server.Close()
	if err != nil {
		return fmt.Errorf("%w: %w", ErrServer, err)
	}

	return nil
}

// ServeHTTP разбирает запрос: CONNECT — туннель, абсолютный URL — обычное проксирование,
// путь без схемы — собственные ручки сторожа (`/status`).
func (server *Server) ServeHTTP(writer http.ResponseWriter, request *http.Request) {
	defer server.fallOnPanic()

	if !server.authorized(request) {
		server.denyAuth(writer, request)

		return
	}

	switch {
	case request.Method == http.MethodConnect:
		server.tunnel(writer, request)
	case request.URL.IsAbs():
		server.forward(writer, request)
	default:
		server.local(writer, request)
	}
}

// authorized сверяет секрет: Basic-пароль из Proxy-Authorization (так его присылает форма
// `http://user:secret@host:port`) или из Authorization — так секрет доходит и при прямом
// запросе `/status`.
func (server *Server) authorized(request *http.Request) bool {
	secret, ok := basicSecret(request.Header.Get(proxyAuthHeader))
	if !ok {
		secret, ok = basicSecret(request.Header.Get(requestAuthHeader))
	}

	if !ok {
		return false
	}

	return subtle.ConstantTimeCompare([]byte(secret), []byte(server.config.Secret)) == 1
}

// denyAuth отвечает 407 и пишет строку журнала.
func (server *Server) denyAuth(writer http.ResponseWriter, request *http.Request) {
	server.config.Journal.Printf("denied %s %s: proxy secret missing or wrong", request.Method, requestTarget(request))

	writer.Header().Set("Proxy-Authenticate", basicPrefix+`realm="`+authRealm+`"`)
	http.Error(writer, deniedAuthMessage, http.StatusProxyAuthRequired)
}

// permit держит вердикт: пропуск только на «IP совпал», иначе 403 с причиной в теле и
// строка в журнале. Причину в самом claude человек не увидит — там будет общая сетевая
// ошибка, поэтому журнал и `/status` и есть канал причины.
func (server *Server) permit(writer http.ResponseWriter, request *http.Request) bool {
	if !server.guardedHost(request) {
		return true
	}

	verdict, err := server.config.Checker.Verdict(request.Context())
	if err != nil {
		message := deniedBlockedPrefix + err.Error()
		server.config.Journal.Printf("blocked %s %s: %s", request.Method, requestTarget(request), message)
		http.Error(writer, message, http.StatusForbidden)

		return false
	}

	if verdict.Allowed() {
		return true
	}

	message := verdict.Message(server.config.ExpectedIP, server.config.CheckURL, server.config.Budget)
	server.config.Journal.Printf("blocked %s %s: %s", request.Method, requestTarget(request), message)
	http.Error(writer, message, http.StatusForbidden)

	return false
}

// guardedHost — ждёт ли цель запроса вердикта. Под вердиктом любой хост, кроме исключений,
// и каждое обращение к такому хосту попадает в таблицу защищаемых; исключения не копятся.
// Имя берётся из запроса (у CONNECT — `request.Host`), без обращения к DNS; запрос без
// имени хоста остаётся под вердиктом — отказ по умолчанию закрытый.
func (server *Server) guardedHost(request *http.Request) bool {
	raw := request.Host
	if request.URL.IsAbs() {
		raw = request.URL.Host
	}

	name := hosts.Name(raw)

	// Строка на хост, а не на каждое соединение: иначе ротируемый журнал забивался бы
	// повторами. Счётчик обращений растёт при этом на каждом запросе.
	if server.exemptHost(name) {
		if server.tell(name) {
			server.config.Journal.Printf("host outside guard: %s", name)
		}

		return false
	}

	if server.config.Seen.Note(name) {
		server.config.Journal.Printf("host under guard: %s", name)
	}

	return true
}

// tell — первое ли это обращение к исключению: только на него и пишется строка журнала.
// Имён у исключений может быть сколько угодно — каждый частный адрес и любой поддомен
// шаблона, — поэтому у памяти о них тот же предел, что у таблицы защищаемых хостов.
func (server *Server) tell(name string) bool {
	server.toldMutex.Lock()
	defer server.toldMutex.Unlock()

	if _, said := server.told[name]; said {
		return false
	}

	if len(server.told) >= seen.DefaultLimit {
		server.tellFull()

		return false
	}

	server.told[name] = struct{}{}

	return true
}

// tellFull говорит о достигнутом пределе памяти об исключениях один раз: молча перестать
// называть новые исключения нельзя, а строка на каждое забила бы журнал. Зовётся под замком.
func (server *Server) tellFull() {
	if server.toldFull {
		return
	}

	server.toldFull = true

	server.config.Journal.Printf(
		"exception log limit %d reached: further exceptions are not named in the journal", seen.DefaultLimit,
	)
}

// exemptHost — исключён ли хост из охраны: хост проверки (иначе проверка замкнулась бы на
// себя), локальная цель или шаблон белого списка.
func (server *Server) exemptHost(name string) bool {
	if name == "" {
		return false
	}

	if server.checkHost != "" && name == server.checkHost {
		return true
	}

	if hosts.Local(name) {
		return true
	}

	return server.exempt.Matches(name)
}

// fallOnPanic валит процесс: net/http сам бы погасил панику и продолжил обслуживать,
// а сторож с неизвестным состоянием обслуживать не должен.
func (server *Server) fallOnPanic() {
	problem := recover()
	if problem == nil {
		return
	}

	server.config.Journal.Printf("panic: %v\n%s", problem, debug.Stack())
	_ = server.config.Journal.Close()

	os.Exit(exitPanic)
}

// New поднимает слушателя по настройке.
func New(config Config) (*Server, error) {
	switch {
	case config.Addr == "":
		return nil, fmt.Errorf("%w: listen address is empty", ErrServer)
	case config.Secret == "":
		return nil, fmt.Errorf("%w: secret is empty", ErrServer)
	case config.Checker == nil || config.Journal == nil:
		return nil, fmt.Errorf("%w: checker and journal are required", ErrServer)
	case config.Seen == nil:
		return nil, fmt.Errorf("%w: seen hosts table is required", ErrServer)
	}

	transport, err := forwardTransport(config.UpstreamProxy)
	if err != nil {
		return nil, err
	}

	exempt, err := hosts.New(config.UnguardedHosts)
	if err != nil {
		return nil, fmt.Errorf("%w: unguarded hosts: %w", ErrServer, err)
	}

	checkHost, err := checkURLHost(config.CheckURL)
	if err != nil {
		return nil, err
	}

	var listenConfig net.ListenConfig

	listener, err := listenConfig.Listen(context.Background(), "tcp", config.Addr)
	if err != nil {
		return nil, fmt.Errorf("%w: listen %s: %w", ErrServer, config.Addr, err)
	}

	server := &Server{
		config:    config,
		listener:  listener,
		server:    nil,
		transport: transport,
		dialer:    &net.Dialer{}, //nolint:exhaustruct // значения по умолчанию net.Dialer
		exempt:    exempt,
		checkHost: checkHost,
		toldMutex: sync.Mutex{},
		told:      make(map[string]struct{}),
		toldFull:  false,
	}

	dropExceptions(server)

	//nolint:exhaustruct // заданы обработчик и срок чтения заголовков, остальное — net/http
	server.server = &http.Server{
		Handler:           server,
		ReadHeaderTimeout: readHeaderTimeout,
	}

	return server, nil
}

// dropExceptions убирает из таблицы хосты, ставшие исключениями, и говорит, сколько их ушло:
// хост, попавший в белый список после того, как его записали, иначе обещал бы защиту,
// которой больше нет.
func dropExceptions(server *Server) {
	dropped, err := server.config.Seen.Filter(server.exemptHost)
	if dropped == 0 {
		return
	}

	// Запись не удалась — записи ещё лежат в файле, и говорить «убраны» про них нельзя.
	if err != nil {
		server.config.Journal.Printf(
			"seen hosts: %d recorded hosts are exceptions now but the table could not be written: %v",
			dropped, err,
		)

		return
	}

	server.config.Journal.Printf("seen hosts: %d recorded hosts are exceptions now and were dropped", dropped)
}

// checkURLHost — хост проверки: охранять его нельзя, иначе проверка ждала бы собственного
// вердикта. Хуки ходят к источнику через этот же прокси, поэтому исключение именное.
func checkURLHost(checkURL string) (string, error) {
	if checkURL == "" {
		return "", nil
	}

	host, err := hosts.HostFromURL(checkURL)
	if err != nil {
		return "", fmt.Errorf("%w: check_url: %w", ErrServer, err)
	}

	return host, nil
}

// basicSecret достаёт пароль из заголовка Basic-авторизации.
func basicSecret(header string) (string, bool) {
	if !strings.HasPrefix(header, basicPrefix) {
		return "", false
	}

	decoded, err := base64.StdEncoding.DecodeString(strings.TrimPrefix(header, basicPrefix))
	if err != nil {
		return "", false
	}

	_, password, found := strings.Cut(string(decoded), ":")
	if !found {
		return "", false
	}

	return password, true
}

// basicEncode собирает значение Basic-авторизации.
func basicEncode(credentials string) string {
	return base64.StdEncoding.EncodeToString([]byte(credentials))
}

// requestTarget — адрес, к которому шли: он и попадает в журнал.
func requestTarget(request *http.Request) string {
	if request.Method == http.MethodConnect {
		return request.Host
	}

	if request.URL.IsAbs() {
		return request.URL.String()
	}

	return request.URL.Path
}

// forwardTransport — транспорт обычного проксирования: верхний прокси из настроек,
// окружение процесса не читается.
func forwardTransport(upstream string) (*http.Transport, error) {
	base, ok := http.DefaultTransport.(*http.Transport)
	if !ok {
		return nil, fmt.Errorf("%w: default transport has unexpected type", ErrServer)
	}

	transport := base.Clone()
	transport.Proxy = nil

	if upstream != "" {
		parsed, err := url.Parse(upstream)
		if err != nil {
			return nil, fmt.Errorf("%w: upstream proxy %q: %w", ErrServer, upstream, err)
		}

		transport.Proxy = http.ProxyURL(parsed)
	}

	return transport, nil
}
