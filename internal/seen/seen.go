// Package seen копит хосты, которые сторож держит под вердиктом: имя, время первой и
// последней встречи и число обращений. Исключения — хост проверки, локальные цели и шаблоны
// белого списка — не копятся вовсе, а попавший в белый список хост уходит из таблицы при
// запуске службы. Таблица читается при запуске — накопленное не теряется при перезапуске — и
// перезаписывается целиком через временный файл и rename: не чаще раза в секунду и
// обязательно при остановке.
package seen

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/kerbyfc/ipguard/internal/hosts"
)

const (
	// DefaultLimit — предел числа записей. Таблица живёт в памяти службы и целиком уходит
	// в `/status`, поэтому предел есть; достигнутый предел не молчит.
	DefaultLimit = 1000
	// DefaultFlush — как часто таблица уходит на диск. Чаще раза в секунду писать нечего:
	// файл перезаписывается целиком.
	DefaultFlush = time.Second

	// fileMode — права файла: он лежит рядом с файлом настроек, в каталоге 0700.
	fileMode os.FileMode = 0o600
	// lineFields — сколько полей в строке файла.
	lineFields = 4
	// borderFields — сколько полей было в прежнем файле: вторым шла снятая колонка границы.
	// Такой файл читается и приводится к нынешнему виду, а не роняет службу владельца.
	borderFields = 5
	// guardedMark и exemptMark — слова снятой колонки границы в прежнем файле.
	guardedMark = "guarded"
	exemptMark  = "exempt"

	header = "# guarded hosts of the guard: name, first seen, last seen, requests\n"
)

// ErrSeen — таблица защищаемых хостов не читается или не пишется.
var ErrSeen = errors.New("ipguard seen hosts failed")

// Entry — хост под вердиктом.
type Entry struct {
	// Host — имя в виде сверки: без порта, в нижнем регистре.
	Host string
	// First и Last — первая и последняя встреча.
	First time.Time
	Last  time.Time
	// Hits — число обращений к хосту за всё время, включая прежние запуски службы.
	Hits int64
}

// Config — из чего собрана таблица. Время и журнал — поля: тесты подставляют свои и не
// зависят от настоящих часов.
type Config struct {
	// Path — файл таблицы в каталоге установки.
	Path string
	// Limit — предел числа записей.
	Limit int
	// Flush — как часто таблица уходит на диск.
	Flush time.Duration
	// Now — часы.
	Now func() time.Time
	// Logf — журнал службы: туда идут достигнутый предел и отказ записи.
	Logf func(format string, args ...any)
}

// Store — таблица защищаемых хостов.
type Store struct {
	config  Config
	mutex   sync.Mutex
	entries map[string]*Entry
	dirty   bool
	flushed time.Time
	told    bool
	ticker  *time.Ticker
	done    chan struct{}
	wait    sync.WaitGroup
	stop    sync.Once
}

// Note отмечает обращение к хосту под вердиктом и говорит, первая ли это встреча.
// Исключения сюда не попадают: таблица отвечает на вопрос «что сторож защищает».
func (store *Store) Note(host string) bool {
	name := hosts.Name(host)
	if name == "" {
		return false
	}

	store.mutex.Lock()
	defer store.mutex.Unlock()

	now := store.config.Now()

	entry, found := store.entries[name]
	if found {
		entry.Hits++
		entry.Last = now

		store.touch(now)

		return false
	}

	if len(store.entries) >= store.config.Limit {
		store.tell()

		return false
	}

	store.entries[name] = &Entry{Host: name, First: now, Last: now, Hits: 1}
	store.touch(now)

	return true
}

// Filter убирает из таблицы хосты, которые стали исключениями, и говорит, сколько их ушло.
// Зовётся при запуске службы: хост, попавший в белый список позже, остался бы в таблице
// защищаемых и врал бы о границе. Таблица после этого сразу уходит на диск; отказ записи
// отдаётся вызывающему — на диске записи ещё лежат, и говорить «убраны» про них нельзя.
func (store *Store) Filter(exempt func(host string) bool) (int, error) {
	store.mutex.Lock()
	defer store.mutex.Unlock()

	dropped := 0

	for name := range store.entries {
		if !exempt(name) {
			continue
		}

		delete(store.entries, name)

		dropped++
	}

	if dropped == 0 {
		return 0, nil
	}

	store.dirty = true

	return dropped, store.write()
}

// Entries — накопленные хосты в порядке перевёрнутых меток имени: зона, домен, поддомен.
func (store *Store) Entries() []Entry {
	store.mutex.Lock()
	defer store.mutex.Unlock()

	return store.sorted()
}

// LimitReached — достигнут ли предел числа записей: новые хосты в таблицу уже не попадают.
func (store *Store) LimitReached() bool {
	store.mutex.Lock()
	defer store.mutex.Unlock()

	return len(store.entries) >= store.config.Limit
}

// Flush пишет таблицу на диск, если есть что писать.
func (store *Store) Flush() error {
	store.mutex.Lock()
	defer store.mutex.Unlock()

	return store.write()
}

// Close останавливает срок записи и сбрасывает таблицу: потеря при остановке службы
// недопустима, поэтому последний сброс идёт без оглядки на срок. Второй вызов только
// сбрасывает: остановка уже случилась.
func (store *Store) Close() error {
	store.stop.Do(func() {
		close(store.done)
		store.ticker.Stop()
		store.wait.Wait()
	})

	return store.Flush()
}

// touch помечает таблицу изменённой и пишет её, если срок вышел. Зовётся под замком.
func (store *Store) touch(now time.Time) {
	store.dirty = true

	if now.Sub(store.flushed) < store.config.Flush {
		return
	}

	err := store.write()
	if err != nil {
		// Отказ записи не валит трафик, но и не молчит: строка журнала называет причину,
		// а таблица остаётся изменённой и уйдёт на диск следующей попыткой.
		store.config.Logf("seen hosts write failed: %v", err)
	}
}

// write перезаписывает файл целиком. Зовётся под замком.
func (store *Store) write() error {
	if !store.dirty {
		return nil
	}

	err := writeAtomic(store.config.Path, render(store.sorted()))
	if err != nil {
		return err
	}

	store.dirty = false
	store.flushed = store.config.Now()

	return nil
}

// sorted — копия записей в порядке перевёрнутых меток. Зовётся под замком.
func (store *Store) sorted() []Entry {
	entries := make([]Entry, 0, len(store.entries))
	for _, entry := range store.entries {
		entries = append(entries, *entry)
	}

	slices.SortFunc(entries, func(left, right Entry) int {
		return hosts.Compare(left.Host, right.Host)
	})

	return entries
}

// tell говорит о достигнутом пределе один раз: строка на каждый отвергнутый хост забила бы
// журнал, а признак предела всё равно виден в `/status`.
func (store *Store) tell() {
	if store.told {
		return
	}

	store.told = true

	store.config.Logf("seen hosts limit %d reached: new hosts are not recorded", store.config.Limit)
}

// run сбрасывает изменённую таблицу по сроку: иначе хост, задетый один раз, лежал бы
// только в памяти до остановки службы.
func (store *Store) run() {
	defer store.wait.Done()

	for {
		select {
		case <-store.done:
			return
		case <-store.ticker.C:
			store.mutex.Lock()
			store.touch(store.config.Now())
			store.mutex.Unlock()
		}
	}
}

// validate проверяет настройку таблицы: значения по умолчанию не подставляются.
func (config Config) validate() error {
	switch {
	case config.Path == "":
		return fmt.Errorf("%w: path is required", ErrSeen)
	case config.Limit < 1:
		return fmt.Errorf("%w: limit must be positive, got %d", ErrSeen, config.Limit)
	case config.Flush <= 0:
		return fmt.Errorf("%w: flush interval must be positive, got %s", ErrSeen, config.Flush)
	case config.Now == nil || config.Logf == nil:
		return fmt.Errorf("%w: clock and journal are required", ErrSeen)
	}

	directory := filepath.Dir(config.Path)

	info, err := os.Stat(directory)
	if err != nil {
		return fmt.Errorf("%w: %s: %w", ErrSeen, directory, err)
	}

	if !info.IsDir() {
		return fmt.Errorf("%w: %s is not a directory", ErrSeen, directory)
	}

	return nil
}

// Open читает таблицу и поднимает срок записи. Негодная настройка, недоступный каталог и
// битый файл — отказ с причиной: сторож не должен молча терять накопленное.
func Open(config Config) (*Store, error) {
	err := config.validate()
	if err != nil {
		return nil, err
	}

	entries, legacy, err := load(config.Path)
	if err != nil {
		return nil, err
	}

	store := &Store{
		config:  config,
		mutex:   sync.Mutex{},
		entries: entries,
		// Прежний файл с колонкой границы помечается изменённым: обычная запись и приводит
		// его к нынешнему виду, отдельного пути для этого нет.
		dirty:   legacy,
		flushed: config.Now(),
		told:    false,
		ticker:  time.NewTicker(config.Flush),
		done:    make(chan struct{}),
		wait:    sync.WaitGroup{},
		stop:    sync.Once{},
	}

	store.wait.Add(1)

	go store.run()

	return store, nil
}

// load читает файл таблицы: файла нет — пустая таблица, битая строка — отказ с номером
// строки, а не молчаливая потеря накопленного. Второй ответ — встретилась ли строка прежнего
// вида с колонкой границы: такой файл надо переписать.
func load(path string) (map[string]*Entry, bool, error) {
	entries := make(map[string]*Entry)
	legacy := false

	content, err := os.ReadFile(path)

	switch {
	case err == nil:
	case os.IsNotExist(err):
		return entries, false, nil
	default:
		return nil, false, fmt.Errorf("%w: %s: %w", ErrSeen, path, err)
	}

	for number, line := range strings.Split(string(content), "\n") {
		if strings.TrimSpace(line) == "" {
			continue
		}

		// Чужая шапка — тоже прежний вид файла: без этого файл, в котором остался один
		// старый комментарий, так и лежал бы с враньём про снятую колонку.
		if strings.HasPrefix(line, "#") {
			legacy = legacy || strings.TrimSpace(line) != strings.TrimSpace(header)

			continue
		}

		entry, border, parseErr := parseLine(line)
		if parseErr != nil {
			return nil, false, fmt.Errorf("%w: %s:%d: %w", ErrSeen, path, number+1, parseErr)
		}

		legacy = legacy || border
		entries[entry.Host] = entry
	}

	return entries, legacy, nil
}

// parseLine разбирает строку файла.
func parseLine(line string) (*Entry, bool, error) {
	parts, border, err := lineParts(strings.TrimRight(line, "\r"))
	if err != nil {
		return nil, false, err
	}

	name := hosts.Name(parts[0])
	if name == "" {
		return nil, false, fmt.Errorf("%w: host name is empty", ErrSeen)
	}

	first, last, err := parseTimes(parts[1], parts[2])
	if err != nil {
		return nil, false, err
	}

	hits, err := strconv.ParseInt(parts[3], 10, 64)
	if err != nil {
		return nil, false, fmt.Errorf("%w: hits %q: %w", ErrSeen, parts[3], err)
	}

	if hits < 1 {
		return nil, false, fmt.Errorf("%w: hits %d must be positive", ErrSeen, hits)
	}

	return &Entry{Host: name, First: first, Last: last, Hits: hits}, border, nil
}

// lineParts — поля строки в нынешнем виде и признак строки прежнего вида. Прежний файл нёс
// вторым полем снятую колонку границы: он читается и переписывается, а не роняет службу.
func lineParts(line string) ([]string, bool, error) {
	parts := strings.Split(line, "\t")

	switch len(parts) {
	case lineFields:
		return parts, false, nil
	case borderFields:
		if parts[1] != guardedMark && parts[1] != exemptMark {
			return nil, false, fmt.Errorf(
				"%w: border %q is neither %s nor %s", ErrSeen, parts[1], guardedMark, exemptMark,
			)
		}

		return []string{parts[0], parts[2], parts[3], parts[4]}, true, nil
	default:
		return nil, false, fmt.Errorf("%w: %d fields instead of %d", ErrSeen, len(parts), lineFields)
	}
}

// parseTimes разбирает время первой и последней встречи.
func parseTimes(rawFirst, rawLast string) (time.Time, time.Time, error) {
	first, err := time.Parse(time.RFC3339, rawFirst)
	if err != nil {
		return time.Time{}, time.Time{}, fmt.Errorf("%w: first seen %q: %w", ErrSeen, rawFirst, err)
	}

	last, err := time.Parse(time.RFC3339, rawLast)
	if err != nil {
		return time.Time{}, time.Time{}, fmt.Errorf("%w: last seen %q: %w", ErrSeen, rawLast, err)
	}

	return first, last, nil
}

// render собирает файл: заголовок и по строке на хост.
func render(entries []Entry) []byte {
	var builder strings.Builder

	builder.WriteString(header)

	for _, entry := range entries {
		fmt.Fprintf(
			&builder, "%s\t%s\t%s\t%d\n",
			entry.Host, entry.First.Format(time.RFC3339), entry.Last.Format(time.RFC3339), entry.Hits,
		)
	}

	return []byte(builder.String())
}

// writeAtomic пишет файл через временный и переименование: со счётчиками дописыванием не
// обойтись, а полупустой таблицы при падении быть не должно.
func writeAtomic(path string, content []byte) error {
	directory := filepath.Dir(path)

	file, err := os.CreateTemp(directory, filepath.Base(path)+".*")
	if err != nil {
		return fmt.Errorf("%w: %s: %w", ErrSeen, directory, err)
	}

	defer func() { _ = os.Remove(file.Name()) }()

	err = fill(file, content)
	if err != nil {
		return err
	}

	err = os.Rename(file.Name(), path)
	if err != nil {
		return fmt.Errorf("%w: %s: %w", ErrSeen, path, err)
	}

	return nil
}

// fill пишет содержимое, ставит права и закрывает файл.
func fill(file *os.File, content []byte) error {
	_, err := file.Write(content)
	if err != nil {
		_ = file.Close()

		return fmt.Errorf("%w: %s: %w", ErrSeen, file.Name(), err)
	}

	err = file.Chmod(fileMode)
	if err != nil {
		_ = file.Close()

		return fmt.Errorf("%w: %s: %w", ErrSeen, file.Name(), err)
	}

	err = file.Close()
	if err != nil {
		return fmt.Errorf("%w: %s: %w", ErrSeen, file.Name(), err)
	}

	return nil
}
