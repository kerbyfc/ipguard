package install

import (
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"

	"github.com/kerbyfc/ipguard/internal/config"
	"github.com/kerbyfc/ipguard/internal/hosts"
)

const (
	// unguardedKey — ключ белого списка в файле настроек.
	unguardedKey = "unguarded_hosts:"
	// guardedKey — ключ снятой настройки: установка убирает его из файла.
	guardedKey = "guarded_hosts:"
	// defaultIndent — отступ пункта, когда в блоке пунктов ещё нет.
	defaultIndent = "  "
)

// ownGuardedComments — начала строк комментария, который над `guarded_hosts` писала сама
// установка. Снимается только он: строку владельца снимать нельзя — она не про этот ключ.
// Legacy: строки остаются русскими — ими писали прежние установки, и по ним же идёт снятие
// ключа со старых файлов.
var ownGuardedComments = []string{
	"# Хосты, которые ждут вердикта проверки IP",
	"# и его поддомены; хосты вне списка идут сразу",
}

// AddUnguardedHost дописывает шаблоны в белый список файла настроек одним текстовым
// редактированием. Файл правится текстом, а не перезаписывается разбором: в нём секрет,
// комментарии и решения владельца, и терять их команда не вправе. Результат правки
// проверяется тем же разбором, каким настройки читает служба, и только потом встаёт на место
// файла. Note — строка отчёта на каждый шаблон.
func AddUnguardedHost(path string, patterns []string) (Change, error) {
	canonical, err := canonicalPatterns(patterns)
	if err != nil {
		return Change{Done: false, Note: ""}, fmt.Errorf("%w: %w", ErrInstall, err)
	}

	current, err := settingsText(path)
	if err != nil {
		return Change{Done: false, Note: ""}, err
	}

	updated, err := insertPattern(current, canonical)
	if err != nil {
		return Change{Done: false, Note: ""}, err
	}

	err = writeVerified(path, updated, canonical)
	if err != nil {
		return Change{Done: false, Note: ""}, err
	}

	notes := make([]string, 0, len(canonical))
	for _, pattern := range canonical {
		notes = append(notes, "added to "+path+": "+pattern)
	}

	return Change{Done: true, Note: strings.Join(notes, "\n")}, nil
}

// canonicalPatterns приводит шаблоны к виду сверки и схлопывает повторы внутри вызова: два
// одинаковых пункта в файле — не решение владельца, а мусор.
func canonicalPatterns(patterns []string) ([]string, error) {
	canonical := make([]string, 0, len(patterns))

	for _, pattern := range patterns {
		value, err := hosts.Canonical(pattern)
		if err != nil {
			return nil, err
		}

		if slices.Contains(canonical, value) {
			continue
		}

		canonical = append(canonical, value)
	}

	return canonical, nil
}

// ensureUnguardedHosts приводит файл настроек к нынешнему контракту: снимает ключ охраны и
// заводит белый список. Уже заданный список владельца не трогается — в нём его решения.
func ensureUnguardedHosts(path string) (Change, error) {
	current, err := os.ReadFile(path)

	switch {
	case err == nil:
	case os.IsNotExist(err):
		// Файл создаёт следующий шаг, и белый список приходит в нём из шаблона.
		return Change{Done: false, Note: "there is no settings file yet, the whitelist comes from the template"}, nil
	default:
		return Change{Done: false, Note: ""}, fmt.Errorf("%w: %s: %w", ErrInstall, path, err)
	}

	set, err := config.UnguardedHostsSet(path)
	if err != nil {
		return Change{Done: false, Note: ""}, fmt.Errorf("%w: %s: %w", ErrInstall, path, err)
	}

	updated, dropped := dropGuardedHosts(string(current))
	if !set {
		updated = appendBlock(updated, unguardedBlock(config.DefaultUnguardedHosts()))
	}

	if !dropped && set {
		return Change{Done: false, Note: "the whitelist is already set in " + path}, nil
	}

	err = writeVerified(path, updated, nil)
	if err != nil {
		return Change{Done: false, Note: ""}, err
	}

	return Change{Done: true, Note: note(path, dropped, set)}, nil
}

// note — строка шага: что именно сделано с файлом настроек.
func note(path string, dropped, set bool) string {
	switch {
	case dropped && set:
		return "guarded_hosts removed, " + path
	case dropped:
		return "guarded_hosts removed, unguarded_hosts added empty, " + path
	default:
		return "unguarded_hosts added empty, " + path
	}
}

// settingsText читает файл настроек. Файла нет — отказ с подсказкой: белый список живёт в
// файле службы, а до установки его ещё нет, и создавать его правкой списка нельзя — в нём
// секрет и ожидаемый адрес, которые заводит только установка.
func settingsText(path string) (string, error) {
	content, err := os.ReadFile(path)

	switch {
	case err == nil:
		return string(content), nil
	case os.IsNotExist(err):
		return "", fmt.Errorf("%w: %s does not exist yet: run `ipguard install` first", ErrInstall, path)
	default:
		return "", fmt.Errorf("%w: %s: %w", ErrInstall, path, err)
	}
}

// writeVerified пишет правку во временный файл рядом, читает её тем же разбором, каким
// настройки читает служба, и только потом переименовывает. Правка, после которой настройки не
// читаются, до файла службы не доходит: иначе команда отчиталась бы «список в силе», а служба
// больше не поднялась бы.
func writeVerified(path, text string, patterns []string) error {
	directory := filepath.Dir(path)

	file, err := os.CreateTemp(directory, filepath.Base(path)+".*")
	if err != nil {
		return fmt.Errorf("%w: %s: %w", ErrInstall, directory, err)
	}

	defer func() { _, _ = removeFile(file.Name()) }()

	err = writeAndClose(file, []byte(text), secretMode)
	if err != nil {
		return err
	}

	err = verifyWhitelist(file.Name(), path, patterns)
	if err != nil {
		return err
	}

	err = os.Rename(file.Name(), path)
	if err != nil {
		return fmt.Errorf("%w: %s: %w", ErrInstall, path, err)
	}

	return nil
}

// verifyWhitelist читает правку разбором настроек: ключ обязан быть назван, а дописанные
// шаблоны — читаться в списке. Проверяются все сразу: один непрочитанный шаблон — брак всей
// правки.
func verifyWhitelist(temporary, path string, patterns []string) error {
	held, set, err := config.UnguardedHostsOf(temporary)
	if err != nil {
		return fmt.Errorf("%w: %s: the edit does not parse as settings: %w", ErrInstall, path, err)
	}

	if !set {
		return fmt.Errorf("%w: %s: the edit left no unguarded_hosts key", ErrInstall, path)
	}

	if len(patterns) == 0 {
		return nil
	}

	known, err := hosts.Canonicalize(held)
	if err != nil {
		return fmt.Errorf("%w: %s: %w", ErrInstall, path, err)
	}

	for _, pattern := range patterns {
		if !slices.Contains(known, pattern) {
			return fmt.Errorf("%w: %s: the edit does not hold the pattern %q", ErrInstall, path, pattern)
		}
	}

	return nil
}

// insertPattern вставляет шаблоны в блок белого списка, сохраняя остальной файл как есть и
// равняясь на отступ лежащих пунктов: `yq` и правка рукой пишут их и без отступа. Список,
// записанный значением в строку, команда не правит: разбор и пересборка потеряли бы форму
// файла, а молча писать не туда нельзя.
func insertPattern(text string, patterns []string) (string, error) {
	lines := strings.Split(text, "\n")

	key := keyLine(lines, unguardedKey)
	if key < 0 {
		return appendBlock(text, unguardedBlock(patterns)), nil
	}

	value := strings.TrimSpace(strings.TrimPrefix(lines[key], unguardedKey))

	switch value {
	case "":
		at, indent := blockEnd(lines, key)

		return strings.Join(insertItems(lines, at, indent, patterns), "\n"), nil
	case "[]":
		lines[key] = unguardedKey

		return strings.Join(insertItems(lines, key+1, defaultIndent, patterns), "\n"), nil
	default:
		return "", fmt.Errorf(
			"%w: unguarded_hosts holds the inline value %q: add the pattern by hand",
			ErrInstall, value,
		)
	}
}

// dropGuardedHosts убирает из файла ключ снятой настройки вместе с его списком и своим
// комментарием: комментарий установки без ключа врал бы о границе, а чужие строки остаются.
func dropGuardedHosts(text string) (string, bool) {
	lines := strings.Split(text, "\n")

	key := keyLine(lines, guardedKey)
	if key < 0 {
		return text, false
	}

	start := key
	for start > 0 && ownComment(lines[start-1]) {
		start--
	}

	end, _ := blockEnd(lines, key)

	kept := make([]string, 0, len(lines))
	kept = append(kept, lines[:start]...)
	kept = append(kept, lines[end:]...)

	return strings.Join(kept, "\n"), true
}

// ownComment — строка комментария, которую над снятым ключом писала сама установка.
func ownComment(line string) bool {
	trimmed := strings.TrimSpace(line)

	for _, own := range ownGuardedComments {
		if strings.HasPrefix(trimmed, own) {
			return true
		}
	}

	return false
}

// keyLine — номер строки ключа верхнего уровня; -1 — ключа нет.
func keyLine(lines []string, key string) int {
	for number, line := range lines {
		if strings.HasPrefix(line, key) {
			return number
		}
	}

	return -1
}

// blockEnd — номер первой строки после блока ключа и отступ его пунктов. Пункт — строка
// `- значение` с любым отступом, включая нулевой; блок кончается на первой строке, которая
// пунктом не является.
func blockEnd(lines []string, key int) (int, string) {
	end := key + 1
	indent := defaultIndent

	for number := key + 1; number < len(lines); number++ {
		found, prefix := itemIndent(lines[number])
		if !found {
			break
		}

		indent = prefix
		end = number + 1
	}

	return end, indent
}

// itemIndent — пункт ли это списка и каков его отступ.
func itemIndent(line string) (bool, string) {
	trimmed := strings.TrimLeft(line, " \t")
	if trimmed != "-" && !strings.HasPrefix(trimmed, "- ") {
		return false, ""
	}

	return true, line[:len(line)-len(trimmed)]
}

// item — строка пункта списка с заданным отступом.
func item(indent, pattern string) string {
	return fmt.Sprintf("%s- %q", indent, pattern)
}

// insertItems вставляет пункты списка в позицию at, сохраняя порядок.
func insertItems(lines []string, at int, indent string, patterns []string) []string {
	items := make([]string, 0, len(patterns))
	for _, pattern := range patterns {
		items = append(items, item(indent, pattern))
	}

	kept := make([]string, 0, len(lines)+len(items))
	kept = append(kept, lines[:at]...)
	kept = append(kept, items...)
	kept = append(kept, lines[at:]...)

	return kept
}

// appendBlock дописывает блок в конец файла, сохраняя прежнее содержимое как есть.
func appendBlock(text, block string) string {
	if text != "" && !strings.HasSuffix(text, "\n") {
		text += "\n"
	}

	if text != "" && !strings.HasSuffix(text, "\n\n") {
		text += "\n"
	}

	return text + block
}

// unguardedBlock — YAML-блок белого списка.
func unguardedBlock(patterns []string) string {
	var builder strings.Builder

	builder.WriteString("# Hosts out of guard: they skip the IP check. A *.domain pattern covers the domain itself\n")
	builder.WriteString("# and its subdomains. Everything else waits for a verdict; the check host and local\n")
	builder.WriteString("# addresses are excluded in code. Add patterns with `ipguard whitelist <pattern>`.\n")

	if len(patterns) == 0 {
		builder.WriteString(unguardedKey + " []\n")

		return builder.String()
	}

	builder.WriteString(unguardedKey + "\n")

	for _, pattern := range patterns {
		builder.WriteString(item(defaultIndent, pattern) + "\n")
	}

	return builder.String()
}
