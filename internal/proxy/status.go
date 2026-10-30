package proxy

import (
	"encoding/json"
	"net/http"
	"slices"
	"time"

	"github.com/kerbyfc/ipguard/internal/hosts"
	"github.com/kerbyfc/ipguard/internal/seen"
)

// SeenHostView — защищаемый хост в ответе `/status`. Время — RFC 3339: это машинный
// договор, а человеку его очеловечивает сама команда.
type SeenHostView struct {
	Host      string `json:"host"`
	FirstSeen string `json:"firstSeen"`
	LastSeen  string `json:"lastSeen"`
	Hits      int64  `json:"hits"`
}

// StatusView — ответ `/status`: вердикт только что выполненной проверки, последняя ошибка и
// обе стороны границы охраны — исключения из настройки и хосты под вердиктом.
// Это и есть способ увидеть причину отказа: в самом claude на пути трафика видна только
// общая сетевая ошибка, без статуса и тела нашего ответа.
type StatusView struct {
	Verdict    string `json:"verdict"`
	Allowed    bool   `json:"allowed"`
	IP         string `json:"ip"`
	LastError  string `json:"lastError"`
	CheckedAt  string `json:"checkedAt"`
	Message    string `json:"message"`
	ExpectedIP string `json:"expectedIp"`
	CheckURL   string `json:"checkUrl"`
	Budget     string `json:"budget"`
	// UnguardedHosts — шаблоны белого списка из настройки, в порядке перевёрнутых меток.
	UnguardedHosts []string `json:"unguardedHosts"`
	// SeenHosts — защищаемые хосты в том же порядке.
	SeenHosts []SeenHostView `json:"seenHosts"`
	// SeenLimitReached — предел числа записей достигнут: новые хосты не копятся.
	SeenLimitReached bool `json:"seenLimitReached"`
}

// local обслуживает собственные ручки сторожа: запрос без абсолютного URL пришёл к прокси
// напрямую, а не через него.
func (server *Server) local(writer http.ResponseWriter, request *http.Request) {
	if request.URL.Path != statusPath {
		http.Error(writer, "claude-ipguard: unknown path "+request.URL.Path, http.StatusNotFound)

		return
	}

	if request.Method != http.MethodGet {
		writer.Header().Set("Allow", http.MethodGet)
		http.Error(writer, "claude-ipguard: "+statusPath+" takes GET", http.StatusMethodNotAllowed)

		return
	}

	server.writeStatus(writer, request)
}

// writeStatus спрашивает вердикт у проверки: подписывается на идущую проверку или начинает
// новую — так же, как соединение.
func (server *Server) writeStatus(writer http.ResponseWriter, request *http.Request) {
	verdict, err := server.config.Checker.Verdict(request.Context())
	if err != nil {
		server.config.Journal.Printf("status check failed: %v", err)
		http.Error(writer, "claude-ipguard: status check failed: "+err.Error(), http.StatusServiceUnavailable)

		return
	}

	view := StatusView{
		Verdict:          string(verdict.Kind),
		Allowed:          verdict.Allowed(),
		IP:               verdict.IP,
		LastError:        verdict.LastError,
		CheckedAt:        verdict.At.Format(time.RFC3339),
		Message:          verdict.Message(server.config.ExpectedIP, server.config.CheckURL, server.config.Budget),
		ExpectedIP:       server.config.ExpectedIP,
		CheckURL:         server.config.CheckURL,
		Budget:           server.config.Budget.String(),
		UnguardedHosts:   server.unguardedPatterns(),
		SeenHosts:        seenHostViews(server.config.Seen.Entries()),
		SeenLimitReached: server.config.Seen.LimitReached(),
	}

	if view.Allowed {
		view.Message = "claude-ipguard: external IP matches " + server.config.ExpectedIP
	}

	writer.Header().Set("Content-Type", "application/json")
	writer.WriteHeader(http.StatusOK)

	encoder := json.NewEncoder(writer)
	encoder.SetIndent("", "  ")

	err = encoder.Encode(view)
	if err != nil {
		server.config.Journal.Printf("status response failed: %v", err)
	}
}

// unguardedPatterns — шаблоны белого списка из настройки в порядке перевёрнутых меток:
// владелец видит исключения тем же порядком, каким печатаются защищаемые хосты.
func (server *Server) unguardedPatterns() []string {
	patterns := make([]string, len(server.config.UnguardedHosts))
	copy(patterns, server.config.UnguardedHosts)

	slices.SortFunc(patterns, hosts.Compare)

	return patterns
}

// seenHostViews переводит записи таблицы в поля ответа.
func seenHostViews(entries []seen.Entry) []SeenHostView {
	views := make([]SeenHostView, 0, len(entries))

	for _, entry := range entries {
		views = append(views, SeenHostView{
			Host:      entry.Host,
			FirstSeen: entry.First.Format(time.RFC3339),
			LastSeen:  entry.Last.Format(time.RFC3339),
			Hits:      entry.Hits,
		})
	}

	return views
}
