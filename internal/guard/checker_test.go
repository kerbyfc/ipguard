package guard_test

import (
	"context"
	"errors"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/kerbyfc/ipguard/internal/config"
	"github.com/kerbyfc/ipguard/internal/guard"
)

const (
	testIP      = "203.0.113.7"
	testOtherIP = "198.51.100.4"
	testURL     = "https://icanhazip.test/"
)

var errNoNetwork = errors.New("dial tcp: no network")

// fakeClock — поддельные часы: сна нет, пауза только двигает время и остаётся в журнале пауз.
type fakeClock struct {
	mutex  sync.Mutex
	now    time.Time
	delays []time.Duration
}

func (clock *fakeClock) Now() time.Time {
	clock.mutex.Lock()
	defer clock.mutex.Unlock()

	return clock.now
}

func (clock *fakeClock) Sleep(_ context.Context, delay time.Duration) error {
	clock.mutex.Lock()
	defer clock.mutex.Unlock()

	clock.delays = append(clock.delays, delay)
	clock.now = clock.now.Add(delay)

	return nil
}

func (clock *fakeClock) Delays() []time.Duration {
	clock.mutex.Lock()
	defer clock.mutex.Unlock()

	return append([]time.Duration(nil), clock.delays...)
}

func TestVerdictMatch(t *testing.T) {
	t.Parallel()

	checker := newChecker(t, newFakeClock(), func(_ context.Context, _, _ string) (string, error) {
		return testIP, nil
	})

	verdict, err := checker.Verdict(context.Background())
	if err != nil {
		t.Fatalf("verdict: %v", err)
	}

	if verdict.Kind != guard.KindOK || !verdict.Allowed() {
		t.Fatalf("verdict %q allowed=%v, want ok and allowed", verdict.Kind, verdict.Allowed())
	}
}

func TestVerdictMismatch(t *testing.T) {
	t.Parallel()

	checker := newChecker(t, newFakeClock(), func(_ context.Context, _, _ string) (string, error) {
		return testOtherIP, nil
	})

	verdict, err := checker.Verdict(context.Background())
	if err != nil {
		t.Fatalf("verdict: %v", err)
	}

	if verdict.Kind != guard.KindMismatch || verdict.Allowed() {
		t.Fatalf("verdict %q allowed=%v, want mismatch and denied", verdict.Kind, verdict.Allowed())
	}

	message := verdict.Message(testIP, testURL, config.DefaultBudget)

	want := "claude-ipguard: blocked: external IP is '" + testOtherIP + "', expected " + testIP
	if message != want {
		t.Fatalf("message %q, want %q", message, want)
	}
}

func TestVerdictNetworkSilent(t *testing.T) {
	t.Parallel()

	clock := newFakeClock()
	checker := newChecker(t, clock, func(_ context.Context, _, _ string) (string, error) {
		return "", errNoNetwork
	})

	verdict, err := checker.Verdict(context.Background())
	if err != nil {
		t.Fatalf("verdict: %v", err)
	}

	if verdict.Kind != guard.KindBudget || verdict.Allowed() {
		t.Fatalf("verdict %q allowed=%v, want budget and denied", verdict.Kind, verdict.Allowed())
	}

	if !strings.Contains(verdict.LastError, errNoNetwork.Error()) {
		t.Fatalf("last error %q does not name the network failure", verdict.LastError)
	}

	message := verdict.Message(testIP, testURL, config.DefaultBudget)
	if !strings.HasPrefix(message, "claude-ipguard: blocked: IP check via "+testURL+" failed within 540 s, last error: ") {
		t.Fatalf("message %q is not the contract wording", message)
	}
}

// TestRetryScheduleAndBudget: паузы 1, 2, 4, 8, 10, дальше по 10 с, и предел 540 с.
func TestRetryScheduleAndBudget(t *testing.T) {
	t.Parallel()

	clock := newFakeClock()
	start := clock.Now()

	var attempts atomic.Int64

	checker := newChecker(t, clock, func(_ context.Context, _, _ string) (string, error) {
		attempts.Add(1)

		return "", errNoNetwork
	})

	verdict, err := checker.Verdict(context.Background())
	if err != nil {
		t.Fatalf("verdict: %v", err)
	}

	if verdict.Kind != guard.KindBudget {
		t.Fatalf("verdict %q, want budget", verdict.Kind)
	}

	delays := clock.Delays()
	checkSchedule(t, delays)

	elapsed := clock.Now().Sub(start)
	if elapsed >= config.DefaultBudget {
		t.Fatalf("elapsed %s, want less than the budget %s", elapsed, config.DefaultBudget)
	}

	if elapsed+10*time.Second < config.DefaultBudget {
		t.Fatalf("elapsed %s stopped earlier than the budget %s allows", elapsed, config.DefaultBudget)
	}

	if attempts.Load() != int64(len(delays))+1 {
		t.Fatalf("attempts %d, want %d", attempts.Load(), len(delays)+1)
	}
}

// TestOneRequestForManyWaiters: N одновременных ждущих при одном медленном ответе проверки —
// к хосту проверки уходит один запрос, и все получают один вердикт.
func TestOneRequestForManyWaiters(t *testing.T) {
	t.Parallel()

	const waiters = 20

	release := make(chan struct{})
	// Ёмкость на всех: без совмещения запросов каждый ждущий поднял бы свой запрос, и тест
	// должен упасть на счётчике, а не повиснуть на этом канале.
	arrived := make(chan struct{}, waiters)

	var requests atomic.Int64

	checker := newChecker(t, newFakeClock(), func(_ context.Context, _, _ string) (string, error) {
		requests.Add(1)

		arrived <- struct{}{}

		<-release

		return testIP, nil
	})

	group, verdicts := startWaiters(t, checker, waiters)

	<-arrived
	// Остальные ждущие приходят, пока запрос в полёте: своих запросов они не поднимают.
	time.Sleep(50 * time.Millisecond)
	close(release)
	group.Wait()

	if requests.Load() != 1 {
		t.Fatalf("requests to the check host: %d, want 1", requests.Load())
	}

	for index, verdict := range verdicts {
		if verdict.Kind != guard.KindOK || verdict.IP != testIP {
			t.Fatalf("waiter %d got %q ip=%q, want ok and %s", index, verdict.Kind, verdict.IP, testIP)
		}
	}
}

// TestNegativeVerdictResolvesAllWaiters: несовпадение IP — такой же результат обещания, как
// совпадение, и получают его все подписчики, а не только первый.
func TestNegativeVerdictResolvesAllWaiters(t *testing.T) {
	t.Parallel()

	const waiters = 20

	release := make(chan struct{})
	arrived := make(chan struct{}, waiters)

	var requests atomic.Int64

	checker := newChecker(t, newFakeClock(), func(_ context.Context, _, _ string) (string, error) {
		requests.Add(1)

		arrived <- struct{}{}

		<-release

		return testOtherIP, nil
	})

	group, verdicts := startWaiters(t, checker, waiters)

	<-arrived
	time.Sleep(50 * time.Millisecond)
	close(release)
	group.Wait()

	if requests.Load() != 1 {
		t.Fatalf("requests to the check host: %d, want 1", requests.Load())
	}

	for index, verdict := range verdicts {
		if verdict.Kind != guard.KindMismatch || verdict.IP != testOtherIP || verdict.Allowed() {
			t.Fatalf(
				"waiter %d got %q ip=%q allowed=%v, want mismatch, %s and denied",
				index, verdict.Kind, verdict.IP, verdict.Allowed(), testOtherIP,
			)
		}
	}
}

// TestSubscriberDuringResolutionGetsVerdict: подписчик, пришедший в момент резолва, не
// теряется — он попадает в этот резолв или подписывается на новое обещание, но ответ
// получает всегда.
func TestSubscriberDuringResolutionGetsVerdict(t *testing.T) {
	t.Parallel()

	const (
		callers = 100
		window  = time.Millisecond
	)

	checker := newChecker(t, newFakeClock(), func(_ context.Context, _, _ string) (string, error) {
		time.Sleep(window)

		return testIP, nil
	})

	var group sync.WaitGroup

	for index := range callers {
		group.Add(1)

		go func() {
			defer group.Done()

			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()

			verdict, err := checker.Verdict(ctx)
			if err != nil {
				t.Errorf("caller %d lost: %v", index, err)

				return
			}

			if verdict.Kind != guard.KindOK {
				t.Errorf("caller %d got %q, want ok", index, verdict.Kind)
			}
		}()
	}

	group.Wait()
}

// TestBudgetExhaustionResolvesAllAndNextStartsNew: исчерпание бюджета — отказ всем
// подписчикам, после чего обещание исчезает и следующее обращение начинает новую проверку.
func TestBudgetExhaustionResolvesAllAndNextStartsNew(t *testing.T) {
	t.Parallel()

	const waiters = 10

	release := make(chan struct{})
	arrived := make(chan struct{}, 1)

	var requests atomic.Int64

	checker := newChecker(t, newFakeClock(), func(_ context.Context, _, _ string) (string, error) {
		requests.Add(1)

		select {
		case arrived <- struct{}{}:
		default:
		}

		<-release

		return "", errNoNetwork
	})

	group, verdicts := startWaiters(t, checker, waiters)

	<-arrived
	time.Sleep(50 * time.Millisecond)
	close(release)
	group.Wait()

	for index, verdict := range verdicts {
		if verdict.Kind != guard.KindBudget || verdict.Allowed() {
			t.Fatalf("waiter %d got %q allowed=%v, want budget and denied", index, verdict.Kind, verdict.Allowed())
		}
	}

	before := requests.Load()

	verdict, err := checker.Verdict(context.Background())
	if err != nil {
		t.Fatalf("verdict after exhaustion: %v", err)
	}

	if verdict.Kind != guard.KindBudget {
		t.Fatalf("verdict after exhaustion %q, want budget", verdict.Kind)
	}

	if requests.Load() <= before {
		t.Fatalf(
			"requests %d after exhaustion, want more than %d: the next connection starts a new check",
			requests.Load(), before,
		)
	}
}

// TestCompletedVerdictIsNotReused: соединение, пришедшее после завершения проверки, ждёт
// новую — прошлый удачный вердикт трафику не отдаётся.
func TestCompletedVerdictIsNotReused(t *testing.T) {
	t.Parallel()

	var requests atomic.Int64

	release := make(chan struct{})
	arrived := make(chan struct{}, 1)

	checker := newChecker(t, newFakeClock(), func(_ context.Context, _, _ string) (string, error) {
		if requests.Add(1) == 1 {
			return testIP, nil
		}

		arrived <- struct{}{}

		<-release

		return testIP, nil
	})

	first, err := checker.Verdict(context.Background())
	if err != nil || first.Kind != guard.KindOK {
		t.Fatalf("first verdict %q: %v", first.Kind, err)
	}

	second := asyncVerdict(t, checker)

	waitStarted(t, arrived)
	expectWaiting(t, second)

	close(release)

	verdict := awaitVerdict(t, second)
	if verdict.Kind != guard.KindOK || verdict.IP != testIP {
		t.Fatalf("second verdict %q ip=%q, want the new ok", verdict.Kind, verdict.IP)
	}

	if requests.Load() != 2 {
		t.Fatalf("requests %d, want 2: the second connection started its own check", requests.Load())
	}
}

// TestSlowCheckIsAwaited: пока проверка в полёте, прошлый вердикт не отдаётся; отмена одного
// ожидающего не убивает общую проверку, и присоединившийся получает её результат.
func TestSlowCheckIsAwaited(t *testing.T) {
	t.Parallel()

	var requests atomic.Int64

	release := make(chan struct{})
	arrived := make(chan struct{}, 1)

	checker := newChecker(t, newFakeClock(), func(_ context.Context, _, _ string) (string, error) {
		if requests.Add(1) == 1 {
			return testIP, nil
		}

		arrived <- struct{}{}

		<-release

		return testIP, nil
	})

	_, err := checker.Verdict(context.Background())
	if err != nil {
		t.Fatalf("first verdict: %v", err)
	}

	joined := asyncVerdict(t, checker)

	waitStarted(t, arrived)

	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()

	verdict, err := checker.Verdict(ctx)
	if !errors.Is(err, guard.ErrCanceled) {
		t.Fatalf(
			"verdict while the check is in flight gave %q: %v, want cancellation, not a stale verdict",
			verdict.Kind, err,
		)
	}

	close(release)

	verdict = awaitVerdict(t, joined)
	if verdict.Kind != guard.KindOK {
		t.Fatalf("joined verdict %q, want ok", verdict.Kind)
	}

	if requests.Load() != 2 {
		t.Fatalf("requests %d, want 2: the cancellation must not start another check", requests.Load())
	}
}

// TestSecondCheckMismatchDeniesTraffic: несовпадение во второй проверке — отказ этому
// соединению; прошлый удачный вердикт его не пускает.
func TestSecondCheckMismatchDeniesTraffic(t *testing.T) {
	t.Parallel()

	var requests atomic.Int64

	checker := newChecker(t, newFakeClock(), func(_ context.Context, _, _ string) (string, error) {
		if requests.Add(1) == 1 {
			return testIP, nil
		}

		return testOtherIP, nil
	})

	_, err := checker.Verdict(context.Background())
	if err != nil {
		t.Fatalf("first verdict: %v", err)
	}

	verdict, err := checker.Verdict(context.Background())
	if err != nil {
		t.Fatalf("second verdict: %v", err)
	}

	if verdict.Kind != guard.KindMismatch || verdict.Allowed() {
		t.Fatalf("second verdict %q allowed=%v, want mismatch and denied", verdict.Kind, verdict.Allowed())
	}

	if requests.Load() != 2 {
		t.Fatalf("requests %d, want 2: the second connection runs a new check", requests.Load())
	}
}

// TestBudgetAfterEarlierVerdictDeniesTraffic: исчерпанный бюджет второй проверки закрывает
// трафик даже после удачной первой — прошлый вердикт больше не действует.
func TestBudgetAfterEarlierVerdictDeniesTraffic(t *testing.T) {
	t.Parallel()

	var requests atomic.Int64

	checker := newChecker(t, newFakeClock(), func(_ context.Context, _, _ string) (string, error) {
		if requests.Add(1) == 1 {
			return testIP, nil
		}

		return "", errNoNetwork
	})

	_, err := checker.Verdict(context.Background())
	if err != nil {
		t.Fatalf("first verdict: %v", err)
	}

	verdict, err := checker.Verdict(context.Background())
	if err != nil {
		t.Fatalf("second verdict: %v", err)
	}

	if verdict.Kind != guard.KindBudget || verdict.Allowed() {
		t.Fatalf("second verdict %q allowed=%v, want budget and denied", verdict.Kind, verdict.Allowed())
	}

	if requests.Load() <= 1 {
		t.Fatalf("requests %d, want more than 1: the second connection runs a new check", requests.Load())
	}
}

// checkSchedule сверяет паузы с расписанием контракта: 1, 2, 4, 8, 10, дальше по 10 с.
func checkSchedule(t *testing.T, delays []time.Duration) {
	t.Helper()

	wantHead := []time.Duration{
		time.Second, 2 * time.Second, 4 * time.Second, 8 * time.Second, 10 * time.Second, 10 * time.Second,
	}

	if len(delays) < len(wantHead) {
		t.Fatalf("delays %v, want at least %v", delays, wantHead)
	}

	for index, want := range wantHead {
		if delays[index] != want {
			t.Fatalf("delay %d is %s, want %s", index, delays[index], want)
		}
	}

	for index := len(wantHead); index < len(delays); index++ {
		if delays[index] != 10*time.Second {
			t.Fatalf("delay %d is %s, want 10s", index, delays[index])
		}
	}
}

// startWaiters поднимает count подписчиков на обещание и отдаёт группу ожидания и ячейки
// вердиктов. Проверку отпускает и группу дожидается вызывающий.
func startWaiters(t *testing.T, checker *guard.Checker, count int) (*sync.WaitGroup, []guard.Verdict) {
	t.Helper()

	verdicts := make([]guard.Verdict, count)
	group := &sync.WaitGroup{}

	for index := range count {
		group.Add(1)

		go func() {
			defer group.Done()

			verdict, err := checker.Verdict(context.Background())
			if err != nil {
				t.Errorf("verdict %d: %v", index, err)

				return
			}

			verdicts[index] = verdict
		}()
	}

	return group, verdicts
}

// asyncVerdict запускает обращение за вердиктом и отдаёт канал с результатом.
func asyncVerdict(t *testing.T, checker *guard.Checker) <-chan guard.Verdict {
	t.Helper()

	verdicts := make(chan guard.Verdict, 1)

	go func() {
		verdict, err := checker.Verdict(context.Background())
		if err != nil {
			t.Errorf("async verdict: %v", err)

			return
		}

		verdicts <- verdict
	}()

	return verdicts
}

// waitStarted ждёт новый запрос к хосту проверки.
func waitStarted(t *testing.T, arrived <-chan struct{}) {
	t.Helper()

	select {
	case <-arrived:
	case <-time.After(time.Second):
		t.Fatal("connection after a completed check did not start a new one")
	}
}

// expectWaiting проверяет, что обращение не получило вердикт, пока проверка в полёте.
func expectWaiting(t *testing.T, verdicts <-chan guard.Verdict) {
	t.Helper()

	select {
	case verdict := <-verdicts:
		t.Fatalf("connection got %q while the new check was in flight, want to wait for it", verdict.Kind)
	case <-time.After(50 * time.Millisecond):
	}
}

// awaitVerdict ждёт вердикт обращения.
func awaitVerdict(t *testing.T, verdicts <-chan guard.Verdict) (verdict guard.Verdict) {
	t.Helper()

	select {
	case verdict = <-verdicts:
		return verdict
	case <-time.After(time.Second):
		t.Fatal("connection did not get the verdict")

		return verdict
	}
}

func newFakeClock() *fakeClock {
	return &fakeClock{mutex: sync.Mutex{}, now: time.Unix(1_700_000_000, 0), delays: nil}
}

func newChecker(t *testing.T, clock guard.Clock, fetch guard.FetchFunc) *guard.Checker {
	t.Helper()

	checker, err := guard.NewChecker(guard.Config{
		ExpectedIP:     testIP,
		CheckURL:       testURL,
		AttemptTimeout: config.DefaultAttemptTimeout,
		RetryDelays:    config.DefaultRetryDelays(),
		Budget:         config.DefaultBudget,
		UpstreamProxy:  "",
		Clock:          clock,
		Fetch:          fetch,
		Logf:           nil,
	})
	if err != nil {
		t.Fatalf("new checker: %v", err)
	}

	t.Cleanup(checker.Stop)

	return checker
}
