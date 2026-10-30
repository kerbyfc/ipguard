// Package guard держит одно обещание о внешнем IP машины: в каждый момент идёт не больше
// одной проверки, её результат получают все подписчики, а завершённый вердикт трафику не
// отдаётся — следующее обращение начинает новую проверку.
package guard

import (
	"errors"
	"fmt"
	"time"
)

// Kind — вердикт проверки.
type Kind string

const (
	// KindOK — внешний IP совпал с ожидаемым.
	KindOK Kind = "ok"
	// KindMismatch — хост проверки ответил другим адресом.
	KindMismatch Kind = "mismatch"
	// KindBudget — за бюджет проверка так и не удалась.
	KindBudget Kind = "budget"
)

var (
	// ErrFetch — запрос к хосту проверки не удался.
	ErrFetch = errors.New("IP request failed")
	// ErrHTTPStatus — хост проверки ответил не 2xx.
	ErrHTTPStatus = errors.New("IP service returned an error status")
	// ErrProxy — негодная настройка верхнего прокси.
	ErrProxy = errors.New("proxy setting is invalid")
	// ErrCanceled — ожидание вердикта прервано остановкой сторожа.
	ErrCanceled = errors.New("IP check canceled")
)

// Verdict — вердикт и время, когда он получен.
type Verdict struct {
	Kind      Kind
	IP        string
	LastError string
	At        time.Time
}

// Allowed — пускать ли трафик по этому вердикту. Пропуск только на KindOK:
// любое другое значение и неизвестный вердикт — отказ.
func (verdict Verdict) Allowed() bool {
	return verdict.Kind == KindOK
}

// Message — текст причины отказа теми же словами, что в проверке хуков
// (scripts/claude-wrapper/mac/ipcheck.sh).
func (verdict Verdict) Message(expectedIP, checkURL string, budget time.Duration) string {
	switch verdict.Kind {
	case KindOK:
		return ""
	case KindMismatch:
		return fmt.Sprintf(
			"claude-ipguard: blocked: external IP is '%s', expected %s",
			verdict.IP,
			expectedIP,
		)
	case KindBudget:
		return fmt.Sprintf(
			"claude-ipguard: blocked: IP check via %s failed within %d s, last error: %s",
			checkURL,
			int(budget/time.Second),
			verdict.LastError,
		)
	default:
		return fmt.Sprintf("claude-ipguard: blocked: unknown verdict %q", string(verdict.Kind))
	}
}

// unknown — «вердикта ещё нет»: им инициализируется обещание до ответа, и никого он не пускает.
func unknown() Verdict {
	return Verdict{Kind: "", IP: "", LastError: "", At: time.Time{}}
}
