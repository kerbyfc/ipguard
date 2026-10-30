package hosts_test

import (
	"errors"
	"slices"
	"testing"

	"github.com/kerbyfc/ipguard/internal/hosts"
)

// TestWildcardCoversDomainAndSubdomains: `*.anthropic.com` покрывает сам домен и любой
// поддомен, включая многоуровневый, но не соседний домен с тем же хвостом и не чужой хост,
// начинающийся с имени домена.
func TestWildcardCoversDomainAndSubdomains(t *testing.T) {
	t.Parallel()

	list, err := hosts.New([]string{"*.anthropic.com"})
	if err != nil {
		t.Fatalf("new list: %v", err)
	}

	cases := map[string]bool{
		"anthropic.com":              true,
		"api.anthropic.com":          true,
		"mcp-proxy.anthropic.com":    true,
		"a.b.c.anthropic.com":        true,
		"evilanthropic.com":          false,
		"anthropic.com.evil.net":     false,
		"anthropic.com.":             true,
		"API.ANTHROPIC.COM":          true,
		"api.anthropic.com:443":      true,
		"api.anthropic.com.evil.net": false,
	}

	for host, want := range cases {
		if got := list.Matches(host); got != want {
			t.Fatalf("matches(%q) = %v, want %v", host, got, want)
		}
	}
}

// TestExactPatternMatchesOnlyItself: имя без звезды — ровно этот хост, поддомены не входят.
func TestExactPatternMatchesOnlyItself(t *testing.T) {
	t.Parallel()

	list, err := hosts.New([]string{"github.com"})
	if err != nil {
		t.Fatalf("new list: %v", err)
	}

	if !list.Matches("github.com") || !list.Matches("GitHub.com.") {
		t.Fatal("exact host does not match")
	}

	if list.Matches("api.github.com") {
		t.Fatal("exact host pattern covered a subdomain")
	}
}

// TestDatadogIntakeIsNotUnderWildcard: intake-хосты Datadog — отдельные домены через дефис,
// поэтому поимённая запись обязана быть, а `*.datadoghq.com` их не ловит.
func TestDatadogIntakeIsNotUnderWildcard(t *testing.T) {
	t.Parallel()

	wildcard, err := hosts.New([]string{"*.datadoghq.com"})
	if err != nil {
		t.Fatalf("new wildcard list: %v", err)
	}

	if wildcard.Matches("browser-intake-us5-datadoghq.com") {
		t.Fatal("*.datadoghq.com matched the hyphenated intake host")
	}

	named, err := hosts.New([]string{"browser-intake-us5-datadoghq.com"})
	if err != nil {
		t.Fatalf("new named list: %v", err)
	}

	if !named.Matches("browser-intake-us5-datadoghq.com") {
		t.Fatal("named intake host does not match")
	}
}

// TestLocalTargetsAreLocal: локальные цели идут мимо проверки — иначе при недоступной
// внешней сети встали бы локальные хуки и мост QA, которые ходят через этот же прокси.
func TestLocalTargetsAreLocal(t *testing.T) {
	t.Parallel()

	cases := map[string]bool{
		"localhost":          true,
		"localhost:8787":     true,
		"LOCALHOST":          true,
		"127.0.0.1":          true,
		"127.1.2.3":          true,
		"[::1]":              true,
		"::1":                true,
		"10.1.2.3":           true,
		"172.16.0.1":         true,
		"172.31.255.255":     true,
		"192.168.1.1":        true,
		"169.254.1.1":        true,
		"fc00::1":            true,
		"fe80::1":            true,
		"printer.local":      true,
		"printer.local:631":  true,
		"api.anthropic.com":  false,
		"8.8.8.8":            false,
		"172.32.0.1":         false,
		"notlocalhost":       false,
		"localhost.evil.net": false,
		"local":              false,
		"":                   false,
	}

	for host, want := range cases {
		if got := hosts.Local(host); got != want {
			t.Fatalf("local(%q) = %v, want %v", host, got, want)
		}
	}
}

// TestCompareOrdersByReversedLabels: порядок — зона, домен, поддомен, без учёта регистра:
// хосты одного домена стоят рядом.
func TestCompareOrdersByReversedLabels(t *testing.T) {
	t.Parallel()

	names := []string{
		"bun.report",
		"API.anthropic.com",
		"storage.googleapis.com",
		"anthropic.com",
		"*.claude.ai",
		"api.claude.ai",
	}

	slices.SortFunc(names, hosts.Compare)

	want := []string{
		"*.claude.ai",
		"api.claude.ai",
		"anthropic.com",
		"API.anthropic.com",
		"storage.googleapis.com",
		"bun.report",
	}

	if !slices.Equal(names, want) {
		t.Fatalf("order %v, want %v", names, want)
	}
}

// TestCanonicalKeepsPatternForm: шаблон приводится к виду сверки — по нему видно, что он уже
// задан, пусть и записан иначе; негодный шаблон — отказ.
func TestCanonicalKeepsPatternForm(t *testing.T) {
	t.Parallel()

	cases := map[string]string{
		"*.Anthropic.COM": "*.anthropic.com",
		"GitHub.com.":     "github.com",
	}

	for pattern, want := range cases {
		got, err := hosts.Canonical(pattern)
		if err != nil {
			t.Fatalf("canonical(%q): %v", pattern, err)
		}

		if got != want {
			t.Fatalf("canonical(%q) = %q, want %q", pattern, got, want)
		}
	}

	// Шаблон из файла настроек может прийти с пробелами по краям: они снимаются.
	trimmed, err := hosts.Canonical("  github.com  ")
	if err != nil {
		t.Fatalf("canonical of a padded pattern: %v", err)
	}

	if trimmed != "github.com" {
		t.Fatalf("canonical of a padded pattern = %q, want %q", trimmed, "github.com")
	}

	_, err = hosts.Canonical("api.*.com")
	if !errors.Is(err, hosts.ErrPattern) {
		t.Fatalf("canonical of a broken pattern gave %v, want a pattern error", err)
	}
}

// TestInvalidPatternsRejected: кривая звезда — отказ настройки, а не шаблон, который молча
// ничего не охраняет.
func TestInvalidPatternsRejected(t *testing.T) {
	t.Parallel()

	for _, pattern := range []string{
		"",                      // пустой шаблон
		"*",                     // звезда без домена
		"api.*.com",             // звезда не в начале
		"*anthropic.com",        // звезда не на границе точки
		"**.anthropic.com",      // двойная звезда
		"https://anthropic.com", // схема
		"http:anthropic.com",    // схема без //
		"anthropic.com:443",     // порт в шаблоне
		"anthropic.com/path",    // путь
	} {
		_, err := hosts.New([]string{pattern})
		if !errors.Is(err, hosts.ErrPattern) {
			t.Fatalf("pattern %q gave %v, want a pattern error", pattern, err)
		}
	}

	// Пустой белый список законен: под вердиктом тогда всё, кроме локальных целей и хоста
	// проверки, и ни с чем он не совпадает.
	empty, err := hosts.New(nil)
	if err != nil {
		t.Fatalf("empty list refused: %v", err)
	}

	if empty.Matches("api.anthropic.com") {
		t.Fatal("empty list matched a host")
	}
}
