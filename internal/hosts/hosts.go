// Package hosts решает, какие адресаты идут мимо проверки IP: вердикта ждёт любой хост,
// кроме локальных целей и шаблонов белого списка. Сверка идёт по имени хоста из запроса,
// без обращений к DNS: шаблон `*.domain` покрывает и сам domain, и любой его поддомен.
package hosts

import (
	"errors"
	"fmt"
	"net"
	"net/url"
	"slices"
	"strings"
)

// ErrPattern — негодный шаблон хоста.
var ErrPattern = errors.New("host pattern is invalid")

const (
	// loopbackName — единственное имя loopback, которое пишут руками.
	loopbackName = "localhost"
	// mdnsSuffix — зона имён локальной сети: `.local` разрешает mDNS, а не внешний DNS.
	mdnsSuffix = ".local"
)

// List — белый список: точные имена и шаблоны поддоменов, которые идут без вердикта.
type List struct {
	exact    []string
	suffixes []string
}

// Matches — совпал ли хост со списком. Имя приводится к виду сверки: без порта, в нижнем
// регистре и без завершающей точки.
func (list *List) Matches(host string) bool {
	name := Name(host)
	if name == "" {
		return false
	}

	if slices.Contains(list.exact, name) {
		return true
	}

	for _, suffix := range list.suffixes {
		// `*.anthropic.com` покрывает anthropic.com и api.anthropic.com, но не
		// evilanthropic.com и не anthropic.com.evil.net: границей служит точка.
		if name == suffix || strings.HasSuffix(name, "."+suffix) {
			return true
		}
	}

	return false
}

// New собирает список из шаблонов. Шаблон — либо точное имя хоста, либо `*.domain`;
// звёздочка допустима только в начале и только перед точкой. Пустой список — пустой белый
// список: под вердиктом тогда всё, кроме локальных целей и хоста проверки.
func New(patterns []string) (*List, error) {
	list := &List{exact: nil, suffixes: nil}

	for _, pattern := range patterns {
		suffix, wildcard, err := parsePattern(pattern)
		if err != nil {
			return nil, err
		}

		if wildcard {
			list.suffixes = append(list.suffixes, suffix)

			continue
		}

		list.exact = append(list.exact, suffix)
	}

	return list, nil
}

// Local — локальная ли цель: имя `localhost`, имя в зоне `.local`, адрес loopback, частной
// сети или link-local. Такие цели идут без вердикта: иначе при недоступной внешней сети
// встали бы локальные хуки и мост QA, которые ходят через этот же прокси.
func Local(host string) bool {
	name := Name(host)
	if name == "" {
		return false
	}

	if name == loopbackName || strings.HasSuffix(name, mdnsSuffix) {
		return true
	}

	address := net.ParseIP(name)
	if address == nil {
		return false
	}

	// IsLoopback — 127.0.0.0/8 и ::1; IsPrivate — 10/8, 172.16/12, 192.168/16 и fc00::/7;
	// IsLinkLocalUnicast — 169.254/16 и fe80::/10.
	return address.IsLoopback() || address.IsPrivate() || address.IsLinkLocalUnicast()
}

// Canonical приводит шаблон к виду сверки и отказывает на негодном: им проверяется шаблон
// команды белого списка, и по нему же видно, что шаблон уже задан.
func Canonical(pattern string) (string, error) {
	suffix, wildcard, err := parsePattern(pattern)
	if err != nil {
		return "", err
	}

	if wildcard {
		return "*." + suffix, nil
	}

	return suffix, nil
}

// Canonicalize приводит список шаблонов к виду сверки: им сверяются уже заданные шаблоны с
// дописываемым и проверяется правка файла настроек.
func Canonicalize(patterns []string) ([]string, error) {
	known := make([]string, 0, len(patterns))

	for _, pattern := range patterns {
		canonical, err := Canonical(pattern)
		if err != nil {
			return nil, err
		}

		known = append(known, canonical)
	}

	return known, nil
}

// Compare сравнивает имена по перевёрнутым меткам: сначала зона, потом домен, потом
// поддомен. В таком порядке хосты одной зоны и одного домена стоят рядом, и список
// читается глазами. Регистр не учитывается.
func Compare(left, right string) int {
	return slices.Compare(reversedLabels(left), reversedLabels(right))
}

// Name приводит имя хоста из запроса к виду сверки: снимает порт, скобки IPv6, завершающую
// точку и приводит регистр к нижнему.
func Name(raw string) string {
	name := strings.TrimSpace(raw)

	host, _, err := net.SplitHostPort(name)
	if err == nil {
		name = host
	} else if strings.HasPrefix(name, "[") && strings.HasSuffix(name, "]") {
		name = strings.TrimSuffix(strings.TrimPrefix(name, "["), "]")
	}

	return strings.ToLower(strings.TrimSuffix(name, "."))
}

// HostFromURL отдаёт имя хоста абсолютного URL без порта.
func HostFromURL(raw string) (string, error) {
	parsed, err := url.Parse(raw)
	if err != nil {
		return "", fmt.Errorf("%w: %s: %w", ErrPattern, raw, err)
	}

	if parsed.Hostname() == "" {
		return "", fmt.Errorf("%w: %s has no host", ErrPattern, raw)
	}

	return Name(parsed.Hostname()), nil
}

// reversedLabels — метки имени в обратном порядке: ключ сортировки по зоне и домену.
func reversedLabels(raw string) []string {
	labels := strings.Split(strings.ToLower(strings.TrimSpace(raw)), ".")
	slices.Reverse(labels)

	return labels
}

// parsePattern разбирает шаблон и отдаёт имя сверки и признак поддоменов.
func parsePattern(pattern string) (string, bool, error) {
	raw := strings.TrimSpace(pattern)
	// Двоеточие — тоже отказ: схема `http:anthropic.com` и порт `anthropic.com:443` — не имя
	// хоста, и после снятия порта шаблон молча покрывал бы не то.
	if strings.ContainsAny(raw, ":/?#") {
		return "", false, fmt.Errorf("%w: %q must be a host name, not a URL or path", ErrPattern, pattern)
	}

	name := Name(raw)
	if name == "" {
		return "", false, fmt.Errorf("%w: empty pattern", ErrPattern)
	}

	if strings.ContainsAny(name, " \t\r\n") {
		return "", false, fmt.Errorf("%w: %q contains whitespace", ErrPattern, pattern)
	}

	if strings.HasPrefix(name, "*.") {
		suffix := strings.TrimPrefix(name, "*.")
		if suffix == "" || strings.HasPrefix(suffix, ".") || strings.Contains(suffix, "*") {
			return "", false, fmt.Errorf("%w: %q must look like *.domain", ErrPattern, pattern)
		}

		return suffix, true, nil
	}

	if strings.Contains(name, "*") {
		return "", false, fmt.Errorf("%w: %q: * is allowed only at the start of *.domain", ErrPattern, pattern)
	}

	return name, false, nil
}
