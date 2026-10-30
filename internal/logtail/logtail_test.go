package logtail_test

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/kerbyfc/ipguard/internal/logtail"
)

const testPoll = 5 * time.Millisecond

// errStopTimeout — слежение не остановилось после отмены.
var errStopTimeout = errors.New("follower did not stop")

// lockedBuffer — вывод слежения, который читает тест, пока его пишет другая горутина.
type lockedBuffer struct {
	mutex sync.Mutex
	data  []byte
}

func (buffer *lockedBuffer) Write(data []byte) (int, error) {
	buffer.mutex.Lock()
	defer buffer.mutex.Unlock()

	buffer.data = append(buffer.data, data...)

	return len(data), nil
}

func (buffer *lockedBuffer) String() string {
	buffer.mutex.Lock()
	defer buffer.mutex.Unlock()

	return string(buffer.data)
}

// run — запущенное слежение: остановка одна на тест, повторный вызов отдаёт тот же исход.
type run struct {
	out    *lockedBuffer
	cancel context.CancelFunc
	done   chan error
	once   sync.Once
	err    error
}

func (started *run) stop() error {
	started.once.Do(func() {
		started.cancel()

		select {
		case started.err = <-started.done:
		case <-time.After(5 * time.Second):
			started.err = errStopTimeout
		}
	})

	return started.err
}

// startFollow запускает слежение и останавливает его в конце теста.
func startFollow(t *testing.T, config logtail.Config) *run {
	t.Helper()

	out := &lockedBuffer{mutex: sync.Mutex{}, data: nil}
	config.Out = out
	config.Poll = testPoll

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)

	started := &run{out: out, cancel: cancel, done: done, once: sync.Once{}, err: nil}

	go func() {
		done <- logtail.Follow(ctx, config)
	}()

	t.Cleanup(func() {
		_ = started.stop()
	})

	return started
}

// waitOutput ждёт, пока вывод не станет ровно ожидаемым.
func waitOutput(t *testing.T, out *lockedBuffer, want string) {
	t.Helper()

	waitUntil(t, "output "+fmt.Sprintf("%q", want), func() bool {
		return out.String() == want
	})
}

// waitContains ждёт, пока в выводе не появится фрагмент.
func waitContains(t *testing.T, out *lockedBuffer, want string) {
	t.Helper()

	waitUntil(t, "output containing "+fmt.Sprintf("%q", want), func() bool {
		return strings.Contains(out.String(), want)
	})
}

// waitUntil ждёт условия, а не фиксированной паузы.
func waitUntil(t *testing.T, what string, condition func() bool) {
	t.Helper()

	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if condition() {
			return
		}

		time.Sleep(time.Millisecond)
	}

	t.Fatalf("timed out waiting for %s", what)
}

func writeLog(t *testing.T, path, content string) {
	t.Helper()

	err := os.WriteFile(path, []byte(content), 0o600)
	if err != nil {
		t.Fatalf("write journal: %v", err)
	}
}

func appendLog(t *testing.T, path, content string) {
	t.Helper()

	file, err := os.OpenFile(path, os.O_APPEND|os.O_WRONLY, 0o600)
	if err != nil {
		t.Fatalf("open journal: %v", err)
	}

	_, err = file.WriteString(content)
	if err != nil {
		t.Fatalf("append journal: %v", err)
	}

	err = file.Close()
	if err != nil {
		t.Fatalf("close journal: %v", err)
	}
}

// TestFollowAppends: строки, дописанные после запуска, доходят до вывода.
func TestFollowAppends(t *testing.T) {
	t.Parallel()

	path := filepath.Join(t.TempDir(), "proxy.log")
	writeLog(t, path, "first\n")

	started := startFollow(t, logtail.Config{Path: path, Lines: 10, Out: nil, Poll: testPoll})
	waitOutput(t, started.out, "first\n")

	appendLog(t, path, "second\n")
	waitOutput(t, started.out, "first\nsecond\n")
}

// TestFollowShowsTail: начальный хвост — ровно последние n строк, а файл короче — все строки.
func TestFollowShowsTail(t *testing.T) {
	t.Parallel()

	path := filepath.Join(t.TempDir(), "proxy.log")
	writeLog(t, path, "one\ntwo\nthree\nfour\nfive\n")

	started := startFollow(t, logtail.Config{Path: path, Lines: 2, Out: nil, Poll: testPoll})
	waitOutput(t, started.out, "four\nfive\n")

	short := filepath.Join(t.TempDir(), "short.log")
	writeLog(t, short, "only\n")

	startedShort := startFollow(t, logtail.Config{Path: short, Lines: 10, Out: nil, Poll: testPoll})
	waitOutput(t, startedShort.out, "only\n")
}

// TestFollowZeroLinesSilentBeforeNew: `-n 0` не печатает прежние строки, а новые печатает.
func TestFollowZeroLinesSilentBeforeNew(t *testing.T) {
	t.Parallel()

	path := filepath.Join(t.TempDir(), "proxy.log")
	writeLog(t, path, "old\n")

	started := startFollow(t, logtail.Config{Path: path, Lines: 0, Out: nil, Poll: testPoll})

	// Пока слежение не открыло файл, дописанная строка может попасть в его начальную
	// позицию; поэтому метки идут до первой видимой — она и доказывает, что файл открыт.
	seen := false

	for attempt := range 100 {
		marker := fmt.Sprintf("new-%d\n", attempt)
		appendLog(t, path, marker)

		if waitOutputFor(started.out, marker, 100*time.Millisecond) {
			seen = true

			break
		}
	}

	if !seen {
		t.Fatalf("no appended line reached the output: %q", started.out.String())
	}

	if strings.Contains(started.out.String(), "old") {
		t.Fatalf("output %q holds lines from before the command", started.out.String())
	}
}

// waitOutputFor ждёт точного вывода не дольше отведённого срока.
func waitOutputFor(out *lockedBuffer, want string, timeout time.Duration) bool {
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if out.String() == want {
			return true
		}

		time.Sleep(time.Millisecond)
	}

	return false
}

// TestFollowWaitsForFile: журнала ещё нет — команда называет ожидаемый файл и начинает
// печатать его строки, как только он появился.
func TestFollowWaitsForFile(t *testing.T) {
	t.Parallel()

	path := filepath.Join(t.TempDir(), "proxy.log")

	started := startFollow(t, logtail.Config{Path: path, Lines: 10, Out: nil, Poll: testPoll})
	waitContains(t, started.out, "waiting for journal "+path)

	writeLog(t, path, "created\n")
	waitContains(t, started.out, "created\n")
}

// TestFollowRefusesMissingDirectory: каталога журнала нет — отказ, а не бесконечное ожидание.
func TestFollowRefusesMissingDirectory(t *testing.T) {
	t.Parallel()

	path := filepath.Join(t.TempDir(), "absent", "proxy.log")
	out := &lockedBuffer{mutex: sync.Mutex{}, data: nil}

	err := logtail.Follow(context.Background(), logtail.Config{
		Path:  path,
		Lines: 10,
		Out:   out,
		Poll:  testPoll,
	})
	if !errors.Is(err, logtail.ErrFollow) {
		t.Fatalf("follow gave %v, want a tail error", err)
	}

	if !strings.Contains(err.Error(), "absent") {
		t.Fatalf("error %q does not name the missing directory", err)
	}
}

// TestFollowStopsOnCancel: отмена контекста — нормальный конец слежения.
func TestFollowStopsOnCancel(t *testing.T) {
	t.Parallel()

	path := filepath.Join(t.TempDir(), "proxy.log")
	writeLog(t, path, "first\n")

	started := startFollow(t, logtail.Config{Path: path, Lines: 10, Out: nil, Poll: testPoll})
	waitOutput(t, started.out, "first\n")

	err := started.stop()
	if err != nil {
		t.Fatalf("follow stopped with %v, want nil", err)
	}
}

// TestFollowRotation: файл заменён под слежением — новые строки продолжают идти, а прежние не
// теряются.
func TestFollowRotation(t *testing.T) {
	t.Parallel()

	directory := t.TempDir()
	path := filepath.Join(directory, "proxy.log")
	writeLog(t, path, "before\n")

	started := startFollow(t, logtail.Config{Path: path, Lines: 10, Out: nil, Poll: testPoll})
	waitOutput(t, started.out, "before\n")

	err := os.Rename(path, path+".1")
	if err != nil {
		t.Fatalf("rotate journal: %v", err)
	}

	writeLog(t, path, "after\n")
	waitOutput(t, started.out, "before\nafter\n")
}

// TestFollowTruncate: файл стал короче на том же дескрипторе — слежение перечитывает его с
// начала, а не молчит о новых строках.
func TestFollowTruncate(t *testing.T) {
	t.Parallel()

	path := filepath.Join(t.TempDir(), "proxy.log")
	writeLog(t, path, "long-line-one\nlong-line-two\n")

	started := startFollow(t, logtail.Config{Path: path, Lines: 10, Out: nil, Poll: testPoll})
	waitOutput(t, started.out, "long-line-one\nlong-line-two\n")

	writeLog(t, path, "short\n")
	waitOutput(t, started.out, "long-line-one\nlong-line-two\nshort\n")
}
