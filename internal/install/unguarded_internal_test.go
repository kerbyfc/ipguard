package install

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestDropGuardedHostsTakesKeyWithComments: снятый ключ уходит вместе со своим списком и
// прилипшим комментарием — комментарий без ключа врал бы о границе охраны.
func TestDropGuardedHostsTakesKeyWithComments(t *testing.T) {
	t.Parallel()

	before := `expected_ip: 203.0.113.9
secret: abc

# Хосты, которые ждут вердикта проверки IP. Шаблон *.domain покрывает и сам домен,
# и его поддомены; хосты вне списка идут сразу.
guarded_hosts:
  - "*.anthropic.com"
  - "github.com"
log_keep: 3
`

	after, dropped := dropGuardedHosts(before)
	if !dropped {
		t.Fatal("the removed key was not found")
	}

	if strings.Contains(after, "guarded_hosts") || strings.Contains(after, "anthropic.com") {
		t.Fatalf("the key or its list survived:\n%s", after)
	}

	if strings.Contains(after, "ждут вердикта проверки IP") {
		t.Fatalf("the comment of the key survived:\n%s", after)
	}

	if !strings.Contains(after, "expected_ip: 203.0.113.9") || !strings.Contains(after, "log_keep: 3") {
		t.Fatalf("other keys were lost:\n%s", after)
	}

	_, dropped = dropGuardedHosts(after)
	if dropped {
		t.Fatal("the key was reported removed twice")
	}
}

// TestDropGuardedHostsKeepsForeignComments: строку владельца над ключом снимать нельзя — она
// не про этот ключ, даже если пустой строки между ними нет.
func TestDropGuardedHostsKeepsForeignComments(t *testing.T) {
	t.Parallel()

	before := `expected_ip: 203.0.113.9
# это моя заметка про VPN, к ключу она не относится
# Хосты, которые ждут вердикта проверки IP. Шаблон *.domain покрывает и сам домен,
guarded_hosts:
  - "*.anthropic.com"
log_keep: 3
`

	after, dropped := dropGuardedHosts(before)
	if !dropped {
		t.Fatal("the removed key was not found")
	}

	if !strings.Contains(after, "это моя заметка про VPN") {
		t.Fatalf("the comment of the owner was taken away:\n%s", after)
	}

	if strings.Contains(after, "ждут вердикта проверки IP") {
		t.Fatalf("the comment of the install survived:\n%s", after)
	}
}

// TestInsertPatternKeepsItemIndent: отступ берётся у лежащих пунктов. Штатный YAML (`yq`,
// правка рукой) пишет их без отступа, и дописанный пункт обязан лечь тем же способом, иначе
// файл перестаёт читаться.
func TestInsertPatternKeepsItemIndent(t *testing.T) {
	t.Parallel()

	cases := map[string]struct {
		before string
		want   string
	}{
		"без отступа": {
			before: "unguarded_hosts:\n- \"first.test\"\nlog_keep: 3\n",
			want:   "unguarded_hosts:\n- \"first.test\"\n- \"second.test\"\nlog_keep: 3\n",
		},
		"отступ четыре": {
			before: "unguarded_hosts:\n    - \"first.test\"\nlog_keep: 3\n",
			want:   "unguarded_hosts:\n    - \"first.test\"\n    - \"second.test\"\nlog_keep: 3\n",
		},
		"ключ последним": {
			before: "log_keep: 3\nunguarded_hosts:\n- \"first.test\"\n",
			want:   "log_keep: 3\nunguarded_hosts:\n- \"first.test\"\n- \"second.test\"\n",
		},
	}

	for name, item := range cases {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			updated, err := insertPattern(item.before, []string{"second.test"})
			if err != nil {
				t.Fatalf("insert: %v", err)
			}

			if updated != item.want {
				t.Fatalf("file after insert:\n%s\nwant:\n%s", updated, item.want)
			}
		})
	}
}

// TestAddUnguardedHostVerifiesEdit: правка, после которой настройки не читаются, до файла
// службы не доходит — иначе команда отчиталась бы «список в силе», а служба не поднялась бы.
func TestAddUnguardedHostVerifiesEdit(t *testing.T) {
	t.Parallel()

	path := filepath.Join(t.TempDir(), "ipguard.yaml")
	// Ключ несёт не список, а отображение: дописанный пункт сделает файл нечитаемым.
	before := "secret: abc\nunguarded_hosts:\n  first: yes\n"

	err := os.WriteFile(path, []byte(before), secretMode)
	if err != nil {
		t.Fatalf("write settings: %v", err)
	}

	_, err = AddUnguardedHost(path, []string{"only.test"})
	if !errors.Is(err, ErrInstall) {
		t.Fatalf("add gave %v, want an install error", err)
	}

	if !strings.Contains(err.Error(), "does not parse as settings") {
		t.Fatalf("refusal %q does not name the cause", err)
	}

	kept, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read settings: %v", err)
	}

	if string(kept) != before {
		t.Fatalf("the settings were rewritten anyway:\n%s", kept)
	}

	leftovers, err := filepath.Glob(filepath.Join(filepath.Dir(path), "ipguard.yaml.*"))
	if err != nil {
		t.Fatalf("glob: %v", err)
	}

	if len(leftovers) != 0 {
		t.Fatalf("temporary files left behind: %v", leftovers)
	}
}

// TestAddUnguardedHostBeforeInstall: файла настроек нет — отказ с подсказкой про установку, а
// не голое «no such file»: белый список живёт в файле службы, и заводит его установка.
func TestAddUnguardedHostBeforeInstall(t *testing.T) {
	t.Parallel()

	_, err := AddUnguardedHost(filepath.Join(t.TempDir(), "ipguard.yaml"), []string{"only.test"})
	if !errors.Is(err, ErrInstall) {
		t.Fatalf("add gave %v, want an install error", err)
	}

	if !strings.Contains(err.Error(), "ipguard install") {
		t.Fatalf("refusal %q does not tell to install first", err)
	}
}

// TestInsertPatternIntoEmptyList: белый список по умолчанию пуст, и первый шаблон
// превращает запись в блок, не теряя остального файла.
func TestInsertPatternIntoEmptyList(t *testing.T) {
	t.Parallel()

	updated, err := insertPattern("secret: abc\nunguarded_hosts: []\nlog_keep: 3\n", []string{"*.example.test"})
	if err != nil {
		t.Fatalf("insert into an empty list: %v", err)
	}

	want := "secret: abc\nunguarded_hosts:\n  - \"*.example.test\"\nlog_keep: 3\n"
	if updated != want {
		t.Fatalf("file after insert:\n%s\nwant:\n%s", updated, want)
	}
}

// TestInsertPatternAfterLastItem: шаблон дописывается в конец блока, прежние остаются.
func TestInsertPatternAfterLastItem(t *testing.T) {
	t.Parallel()

	before := "unguarded_hosts:\n  - \"first.test\"\n  - \"second.test\"\nlog_keep: 3\n"

	updated, err := insertPattern(before, []string{"third.test"})
	if err != nil {
		t.Fatalf("insert after the last item: %v", err)
	}

	want := "unguarded_hosts:\n  - \"first.test\"\n  - \"second.test\"\n  - \"third.test\"\nlog_keep: 3\n"
	if updated != want {
		t.Fatalf("file after insert:\n%s\nwant:\n%s", updated, want)
	}
}

// TestInsertPatternWithoutKey: ключа нет — дописывается целый блок с комментарием.
func TestInsertPatternWithoutKey(t *testing.T) {
	t.Parallel()

	updated, err := insertPattern("secret: abc\n", []string{"only.test"})
	if err != nil {
		t.Fatalf("insert without the key: %v", err)
	}

	if !strings.HasPrefix(updated, "secret: abc\n") {
		t.Fatalf("the file lost its head:\n%s", updated)
	}

	if !strings.Contains(updated, "unguarded_hosts:\n  - \"only.test\"\n") {
		t.Fatalf("the block was not appended:\n%s", updated)
	}
}

// TestInsertPatternRefusesInlineList: список значением в строку команда не правит — разбор и
// пересборка потеряли бы форму файла, а писать не туда нельзя.
func TestInsertPatternRefusesInlineList(t *testing.T) {
	t.Parallel()

	_, err := insertPattern("unguarded_hosts: [\"first.test\"]\n", []string{"second.test"})
	if !errors.Is(err, ErrInstall) {
		t.Fatalf("insert into an inline list gave %v, want an install error", err)
	}
}

// TestAddUnguardedHostCanonicalises: шаблон проверяется и приводится к виду сверки, негодный
// — отказ без правки файла.
func TestAddUnguardedHostCanonicalises(t *testing.T) {
	t.Parallel()

	path := filepath.Join(t.TempDir(), "ipguard.yaml")
	before := "secret: abc\nunguarded_hosts: []\n"

	err := os.WriteFile(path, []byte(before), secretMode)
	if err != nil {
		t.Fatalf("write settings: %v", err)
	}

	change, err := AddUnguardedHost(path, []string{"*.Example.TEST"})
	if err != nil {
		t.Fatalf("add pattern: %v", err)
	}

	if !change.Done || !strings.Contains(change.Note, "*.example.test") {
		t.Fatalf("change %+v does not report the pattern", change)
	}

	content, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read settings: %v", err)
	}

	if !strings.Contains(string(content), "  - \"*.example.test\"") {
		t.Fatalf("settings %q do not hold the pattern", content)
	}

	_, err = AddUnguardedHost(path, []string{"api.*.test"})
	if !errors.Is(err, ErrInstall) {
		t.Fatalf("a broken pattern gave %v, want an install error", err)
	}

	after, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read settings: %v", err)
	}

	if strings.Contains(string(after), "api.") {
		t.Fatalf("the broken pattern was written anyway:\n%s", after)
	}
}

// TestAddUnguardedHostAddsSeveralPatterns: несколько шаблонов ложатся одной правкой, повторы
// схлопываются, отступ лежащих пунктов сохраняется, а Note несёт строку отчёта на каждый
// шаблон — все они проверены разбором до переименования файла.
func TestAddUnguardedHostAddsSeveralPatterns(t *testing.T) {
	t.Parallel()

	path := filepath.Join(t.TempDir(), "ipguard.yaml")
	before := "secret: abc\nunguarded_hosts:\n    - \"first.test\"\nlog_keep: 3\n"

	err := os.WriteFile(path, []byte(before), secretMode)
	if err != nil {
		t.Fatalf("write settings: %v", err)
	}

	change, err := AddUnguardedHost(path, []string{"Second.TEST", "second.test", "*.third.test"})
	if err != nil {
		t.Fatalf("add patterns: %v", err)
	}

	if !change.Done {
		t.Fatalf("add reported %+v without doing anything", change)
	}

	want := "secret: abc\nunguarded_hosts:\n    - \"first.test\"\n" +
		"    - \"second.test\"\n    - \"*.third.test\"\nlog_keep: 3\n"
	if got := readSettingsFile(t, path); got != want {
		t.Fatalf("settings after the edit:\n%s\nwant:\n%s", got, want)
	}

	notes := strings.Split(change.Note, "\n")
	wantNotes := []string{
		"added to " + path + ": second.test",
		"added to " + path + ": *.third.test",
	}
	if len(notes) != len(wantNotes) {
		t.Fatalf("notes %v, want %v", notes, wantNotes)
	}

	for index, note := range wantNotes {
		if notes[index] != note {
			t.Fatalf("notes %v, want %v", notes, wantNotes)
		}
	}
}

// readSettingsFile читает файл настроек или валит тест.
func readSettingsFile(t *testing.T, path string) string {
	t.Helper()

	content, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read settings: %v", err)
	}

	return string(content)
}

// TestEnsureUnguardedHostsWrapsRefusal: нечитаемый файл настроек — ошибка установки с
// причиной, а не шаг, который молча ничего не сделал.
func TestEnsureUnguardedHostsWrapsRefusal(t *testing.T) {
	t.Parallel()

	_, err := ensureUnguardedHosts(t.TempDir())
	if !errors.Is(err, ErrInstall) {
		t.Fatalf("ensureUnguardedHosts gave %v, want an install error", err)
	}
}
