package proxy

import (
	"errors"
	"fmt"
	"io"
	"log"
	"os"
	"path/filepath"
	"strconv"
	"sync"
)

// ErrJournal — журнал не открылся.
var ErrJournal = errors.New("ipguard journal failed")

// Journal — журнал сторожа: ротируемый по размеру файл из настроек и, при запуске в первом
// плане, тот же текст в stderr, чтобы причина была видна в терминале. Под службой зеркала
// нет: её stderr уходит в файл, который никто не ротирует, и второй неограниченный файл с
// тем же текстом рос бы без предела.
type Journal struct {
	file   *rotatingFile
	logger *log.Logger
}

// Printf пишет строку журнала.
func (journal *Journal) Printf(format string, args ...any) {
	journal.logger.Printf(format, args...)
}

// Close закрывает файл журнала.
func (journal *Journal) Close() error {
	if journal.file == nil {
		return nil
	}

	return journal.file.Close()
}

// rotatingFile — файл журнала, переименовывающий себя при переполнении. Строки пишут
// обработчики соединений из разных горутин, поэтому запись и ротация идут под замком.
type rotatingFile struct {
	mutex    sync.Mutex
	path     string
	maxBytes int64
	keep     int
	file     *os.File
	size     int64
	broken   error
}

// Write пишет строку, ротируя файл перед переполнением.
func (writer *rotatingFile) Write(line []byte) (int, error) {
	writer.mutex.Lock()
	defer writer.mutex.Unlock()

	if writer.broken != nil {
		return 0, writer.broken
	}

	if writer.size > 0 && writer.size+int64(len(line)) > writer.maxBytes {
		err := writer.rotate()
		if err != nil {
			writer.fall(err)
		}
	}

	written, err := writer.file.Write(line)
	writer.size += int64(written)

	if err != nil {
		return written, fmt.Errorf("%w: %s: %w", ErrJournal, writer.path, err)
	}

	return written, nil
}

// fall роняет процесс сорвавшейся ротацией: файл уже закрыт, и сторож без журнала работал бы
// вслепую — журнал единственное, по чему видно, что он держит трафик. Причина идёт прямо в
// stderr (под службой это её файл вывода): обработчик паники пишет в тот же отказавший
// журнал и до владельца её не донесёт.
func (writer *rotatingFile) fall(cause error) {
	writer.broken = cause

	_, _ = fmt.Fprintf(os.Stderr, "ipguard: journal rotation failed: %v\n", cause)

	panic(cause)
}

// Close закрывает файл.
func (writer *rotatingFile) Close() error {
	writer.mutex.Lock()
	defer writer.mutex.Unlock()

	err := writer.file.Close()
	if err != nil {
		return fmt.Errorf("%w: %w", ErrJournal, err)
	}

	return nil
}

// rotate сдвигает прежние файлы и открывает пустой нынешний.
func (writer *rotatingFile) rotate() error {
	err := writer.file.Close()
	if err != nil {
		return fmt.Errorf("%w: %s: %w", ErrJournal, writer.path, err)
	}

	// Самый старый файл уходит целиком: держать больше keep штук незачем.
	err = removeJournalFile(writer.name(writer.keep))
	if err != nil {
		return err
	}

	for index := writer.keep - 1; index >= 0; index-- {
		err = renameJournalFile(writer.name(index), writer.name(index+1))
		if err != nil {
			return err
		}
	}

	file, size, err := openJournalFile(writer.path)
	if err != nil {
		return err
	}

	writer.file = file
	writer.size = size

	return nil
}

// name — имя файла поколения index: 0 — нынешний, дальше `.1`, `.2` и так до keep.
func (writer *rotatingFile) name(index int) string {
	if index == 0 {
		return writer.path
	}

	return writer.path + "." + strconv.Itoa(index)
}

// OpenJournal открывает журнал по пути из настроек, создавая каталог. Файл вырос больше
// maxBytes — он переименовывается в `.1`, прежние сдвигаются дальше, и старше keep штук не
// хранится: журнал сторожа живёт годами и без ротации растёт без предела.
//
// mirror — куда дублировать строки, кроме файла (запуск в первом плане — stderr); под службой
// он нулевой, и строка идёт только в ротируемый файл. Зеркало стоит перед файлом: отказ файла
// не должен отнимать у владельца единственный оставшийся вывод.
func OpenJournal(path string, maxBytes int64, keep int, mirror io.Writer) (*Journal, error) {
	err := os.MkdirAll(filepath.Dir(path), 0o700)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrJournal, err)
	}

	file, err := openRotatingFile(path, maxBytes, keep)
	if err != nil {
		return nil, err
	}

	var sink io.Writer = file
	if mirror != nil {
		sink = io.MultiWriter(mirror, file)
	}

	return &Journal{
		file:   file,
		logger: log.New(sink, "", log.LstdFlags),
	}, nil
}

// NewJournal — журнал в произвольный writer: так его подменяют тесты.
func NewJournal(writer io.Writer) *Journal {
	return &Journal{
		file:   nil,
		logger: log.New(writer, "", log.LstdFlags),
	}
}

// openRotatingFile открывает файл журнала и запоминает его нынешний размер.
func openRotatingFile(path string, maxBytes int64, keep int) (*rotatingFile, error) {
	if maxBytes <= 0 || keep < 1 {
		return nil, fmt.Errorf(
			"%w: rotation needs a positive size and at least one kept file, got %d bytes and %d files",
			ErrJournal, maxBytes, keep,
		)
	}

	file, size, err := openJournalFile(path)
	if err != nil {
		return nil, err
	}

	//nolint:exhaustruct // mutex нулевой по смыслу
	return &rotatingFile{
		path:     path,
		maxBytes: maxBytes,
		keep:     keep,
		file:     file,
		size:     size,
		broken:   nil,
	}, nil
}

// openJournalFile открывает файл журнала на дозапись и отдаёт его нынешний размер.
func openJournalFile(path string) (*os.File, int64, error) {
	file, err := os.OpenFile(path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o600)
	if err != nil {
		return nil, 0, fmt.Errorf("%w: %w", ErrJournal, err)
	}

	info, err := file.Stat()
	if err != nil {
		_ = file.Close()

		return nil, 0, fmt.Errorf("%w: %s: %w", ErrJournal, path, err)
	}

	return file, info.Size(), nil
}

// removeJournalFile удаляет файл поколения; его отсутствие — не ошибка.
func removeJournalFile(path string) error {
	err := os.Remove(path)
	if err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("%w: %s: %w", ErrJournal, path, err)
	}

	return nil
}

// renameJournalFile сдвигает файл поколения; его отсутствие — не ошибка.
func renameJournalFile(from, to string) error {
	err := os.Rename(from, to)
	if err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("%w: %s -> %s: %w", ErrJournal, from, to, err)
	}

	return nil
}
