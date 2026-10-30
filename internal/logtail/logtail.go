// Package logtail — хвост файла журнала в реальном времени: последние строки, затем
// дописываемые следом, с учётом переименования файла при ротации.
package logtail

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"time"
)

const (
	// DefaultLines — сколько последних строк показывается сначала, как у tail -f.
	DefaultLines = 10
	// DefaultPoll — пауза между проверками файла: без busy-wait и с задержкой меньше секунды.
	DefaultPoll = 300 * time.Millisecond

	readChunk = 32 << 10
)

// ErrFollow — хвост журнала не читается.
var ErrFollow = errors.New("ipguard journal tail failed")

// Config — что читать и куда писать.
type Config struct {
	// Path — путь файла журнала.
	Path string
	// Lines — сколько последних строк показать сначала; 0 — только новые.
	Lines int
	// Out — куда идут строки.
	Out io.Writer
	// Poll — пауза между проверками файла.
	Poll time.Duration
}

// follower — открытый файл журнала и позиция прочитанного.
type follower struct {
	path    string
	out     io.Writer
	file    *os.File
	offset  int64
	pending []byte
	// tailOnOpen — при следующем появлении файла показать его хвост: так ждут журнал,
	// которого ещё нет; после ротации файл читается с начала.
	tailOnOpen bool
}

// checkDirectory требует существующий каталог журнала: ждать файл в несуществующем каталоге
// значило бы молчать о неверном пути.
func (follower *follower) checkDirectory() error {
	directory := filepath.Dir(follower.path)

	info, err := os.Stat(directory)
	if err != nil {
		return fmt.Errorf("%w: %s: %w", ErrFollow, directory, err)
	}

	if !info.IsDir() {
		return fmt.Errorf("%w: %s is not a directory", ErrFollow, directory)
	}

	return nil
}

// openTail открывает файл и печатает его последние lines строк.
func (follower *follower) openTail(lines int) error {
	file, err := os.Open(follower.path)
	if err != nil {
		return fmt.Errorf("%w: %s: %w", ErrFollow, follower.path, err)
	}

	info, err := file.Stat()
	if err != nil {
		_ = file.Close()

		return fmt.Errorf("%w: %s: %w", ErrFollow, follower.path, err)
	}

	follower.file = file
	follower.offset = 0
	follower.pending = nil
	follower.tailOnOpen = false

	start, err := tailStart(file, info.Size(), lines)
	if err != nil {
		return err
	}

	follower.offset = start

	err = follower.readNew()
	if err != nil {
		return err
	}

	// Последняя строка файла может быть без перевода строки: хвост показывает её как есть.
	return follower.flushPending()
}

// openStart открывает файл с начала: так читается новый файл после ротации.
func (follower *follower) openStart() error {
	file, err := os.Open(follower.path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil
		}

		return fmt.Errorf("%w: %s: %w", ErrFollow, follower.path, err)
	}

	follower.file = file
	follower.offset = 0
	follower.pending = nil
	follower.tailOnOpen = false

	return follower.readNew()
}

// poll сверяет файл по пути с открытым и дочитывает новые строки.
func (follower *follower) poll(lines int) error {
	info, err := os.Stat(follower.path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			// Переименованный файл ещё виден через дескриптор; новый появится следом.
			return nil
		}

		return fmt.Errorf("%w: %s: %w", ErrFollow, follower.path, err)
	}

	if follower.file == nil {
		if follower.tailOnOpen {
			err = follower.openTail(lines)
			if errors.Is(err, os.ErrNotExist) {
				return nil
			}

			return err
		}

		return follower.openStart()
	}

	current, err := follower.file.Stat()
	if err != nil {
		return fmt.Errorf("%w: %s: %w", ErrFollow, follower.path, err)
	}

	if !os.SameFile(current, info) {
		return follower.reopen()
	}

	if info.Size() < follower.offset {
		return follower.truncate()
	}

	return follower.readNew()
}

// reopen дочитывает прежний файл, закрывает его и открывает новый с начала.
func (follower *follower) reopen() error {
	err := follower.readNew()
	if err != nil {
		return err
	}

	err = follower.flushPending()
	if err != nil {
		return err
	}

	follower.close()

	return follower.openStart()
}

// truncate перечитывает файл, ставший короче: тот же дескриптор, но прежние строки уже
// заменены.
func (follower *follower) truncate() error {
	err := follower.flushPending()
	if err != nil {
		return err
	}

	follower.offset = 0

	return follower.readNew()
}

// readNew дочитывает файл от текущей позиции до его нынешнего конца.
func (follower *follower) readNew() error {
	info, err := follower.file.Stat()
	if err != nil {
		return fmt.Errorf("%w: %s: %w", ErrFollow, follower.path, err)
	}

	size := info.Size()
	if size <= follower.offset {
		return nil
	}

	_, err = follower.file.Seek(follower.offset, io.SeekStart)
	if err != nil {
		return fmt.Errorf("%w: %s: %w", ErrFollow, follower.path, err)
	}

	buffer := make([]byte, readChunk)
	remaining := size - follower.offset

	for remaining > 0 {
		limit := int64(len(buffer))
		if remaining < limit {
			limit = remaining
		}

		read, readErr := follower.file.Read(buffer[:limit])
		if read > 0 {
			follower.offset += int64(read)
			remaining -= int64(read)

			err = follower.emit(buffer[:read])
			if err != nil {
				return err
			}
		}

		if readErr != nil {
			if errors.Is(readErr, io.EOF) {
				return nil
			}

			return fmt.Errorf("%w: %s: %w", ErrFollow, follower.path, readErr)
		}
	}

	return nil
}

// emit печатает только целые строки: недописанный остаток ждёт в pending.
func (follower *follower) emit(data []byte) error {
	follower.pending = append(follower.pending, data...)

	for {
		index := bytes.IndexByte(follower.pending, '\n')
		if index < 0 {
			return nil
		}

		_, err := follower.out.Write(follower.pending[:index+1])
		if err != nil {
			return fmt.Errorf("%w: %w", ErrFollow, err)
		}

		follower.pending = follower.pending[index+1:]
	}
}

// flushPending печатает остаток без перевода строки, когда он уже не пополнится.
func (follower *follower) flushPending() error {
	if len(follower.pending) == 0 {
		return nil
	}

	_, err := follower.out.Write(follower.pending)
	follower.pending = nil

	if err != nil {
		return fmt.Errorf("%w: %w", ErrFollow, err)
	}

	return nil
}

// close закрывает файл; на остановке команды ошибка закрытия не меняет код возврата.
func (follower *follower) close() {
	if follower.file == nil {
		return
	}

	_ = follower.file.Close()
	follower.file = nil
}

// tailStart ищет начало последних lines строк файла размером size. Перевод строки в конце
// файла завершает последнюю строку, а не начинает пустую.
func tailStart(file *os.File, size int64, lines int) (int64, error) {
	if lines <= 0 || size == 0 {
		return size, nil
	}

	buffer := make([]byte, readChunk)
	position := size
	found := 0

	for position > 0 {
		start := position - int64(len(buffer))
		if start < 0 {
			start = 0
		}

		read, err := file.ReadAt(buffer[:position-start], start)
		if err != nil && !errors.Is(err, io.EOF) {
			return 0, fmt.Errorf("%w: %s: %w", ErrFollow, file.Name(), err)
		}

		offset, seen, done := scanNewlines(buffer[:read], start, size, lines, found)
		if done {
			return offset, nil
		}

		found = seen
		position = start
	}

	return 0, nil
}

// scanNewlines ищет начало lines строк в куске файла с абсолютным смещением start. found —
// сколько переводов строки уже нашли правее; перевод строки в конце файла не считается.
func scanNewlines(chunk []byte, start, size int64, lines, found int) (int64, int, bool) {
	for index := len(chunk) - 1; index >= 0; index-- {
		if chunk[index] != '\n' {
			continue
		}

		if start+int64(index) == size-1 {
			// Перевод строки в конце файла завершает последнюю строку.
			continue
		}

		found++
		if found == lines {
			return start + int64(index) + 1, found, true
		}
	}

	return 0, found, false
}

// Follow печатает последние Lines строк файла и дописывает новые до отмены ctx. Отмена —
// нормальный конец: возвращается nil. Файла ещё нет — Follow ждёт его появления, сказав об
// этом одной строкой. Каталога нет или путь не раскрывается — отказ с причиной.
func Follow(ctx context.Context, config Config) error {
	err := validate(config)
	if err != nil {
		return err
	}

	//nolint:exhaustruct // поля заполняются по мере открытия файла
	follower := &follower{
		path: config.Path,
		out:  config.Out,
	}

	err = follower.checkDirectory()
	if err != nil {
		return err
	}

	err = follower.openTail(config.Lines)
	if errors.Is(err, os.ErrNotExist) {
		follower.tailOnOpen = true

		_, _ = fmt.Fprintf(
			config.Out, "ipguard: waiting for journal %s: file does not exist yet\n", config.Path,
		)
	} else if err != nil {
		return err
	}

	ticker := time.NewTicker(config.Poll)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			follower.close()

			return nil
		case <-ticker.C:
			err = follower.poll(config.Lines)
			if err != nil {
				follower.close()

				return err
			}
		}
	}
}

// validate проверяет настройки, без которых слежение теряет смысл.
func validate(config Config) error {
	if config.Path == "" {
		return fmt.Errorf("%w: log path is empty", ErrFollow)
	}

	if config.Out == nil {
		return fmt.Errorf("%w: output writer is nil", ErrFollow)
	}

	if config.Lines < 0 {
		return fmt.Errorf("%w: lines %d is negative", ErrFollow, config.Lines)
	}

	if config.Poll <= 0 {
		return fmt.Errorf("%w: poll interval %s is not positive", ErrFollow, config.Poll)
	}

	return nil
}
