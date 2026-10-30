package guard

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"time"
)

// ErrConfig — неполная настройка проверки.
var ErrConfig = errors.New("checker config is incomplete")

// Config — настройка проверки IP.
type Config struct {
	ExpectedIP     string
	CheckURL       string
	AttemptTimeout time.Duration
	RetryDelays    []time.Duration
	Budget         time.Duration
	UpstreamProxy  string
	Clock          Clock
	Fetch          FetchFunc
	Logf           func(format string, args ...any)
}

// Checker раздаёт одно обещание о внешнем IP. В каждый момент идёт не более одной проверки:
// пришедший во время неё подписывается на неё. Завершённый вердикт не хранится: следующее
// обращение начинает новую проверку и ждёт её.
type Checker struct {
	config Config
	ctx    context.Context //nolint:containedctx // контекст жизни сторожа: Stop прерывает ожидание
	cancel context.CancelFunc
	mutex  sync.Mutex
	active *promise
}

// promise — идущая проверка и её подписчики: done закрывается с готовым verdict.
type promise struct {
	done    chan struct{}
	verdict Verdict
}

// Verdict отдаёт результат проверки: подписывается на идущее обещание или начинает новое.
// Завершённая проверка трафику не отдаётся — пришедший после неё ждёт следующую.
func (checker *Checker) Verdict(ctx context.Context) (Verdict, error) {
	checker.mutex.Lock()

	active := checker.active
	if active == nil {
		active = checker.start(ctx)
	}

	checker.mutex.Unlock()

	select {
	case <-active.done:
		return active.verdict, nil
	case <-ctx.Done():
		return unknown(), fmt.Errorf("%w: %w", ErrCanceled, ctx.Err())
	case <-checker.ctx.Done():
		return unknown(), fmt.Errorf("%w: %w", ErrCanceled, checker.ctx.Err())
	}
}

// start заводит проверку и отдаёт её обещание. Вызывается под замком. Контекст проверки
// наследует значения запроса, но не его отмену: проверка живёт дольше соединения, а Stop
// по-прежнему прерывает её через контекст сторожа.
func (checker *Checker) start(ctx context.Context) *promise {
	active := &promise{done: make(chan struct{}), verdict: unknown()}
	checker.active = active

	checkCtx, cancel := checker.checkContext(ctx)

	go func() {
		defer cancel()

		checker.execute(checkCtx, active)
	}()

	return active
}

// checkContext отделяет проверку от отмены запроса клиента, но оставляет её управляемой Stop.
func (checker *Checker) checkContext(ctx context.Context) (context.Context, context.CancelFunc) {
	detached, cancel := context.WithCancel(context.WithoutCancel(ctx))
	stop := context.AfterFunc(checker.ctx, cancel)

	return detached, func() {
		stop()
		cancel()
	}
}

// Stop прерывает идущую проверку и ожидание вердикта.
func (checker *Checker) Stop() {
	checker.cancel()
}

// execute доводит проверку до вердикта, резолвит всех подписчиков и убирает обещание.
// Резолв (вердикт и снятие обещания) идёт под тем же замком, что и подписка, поэтому
// подписчик не может потеряться между резолвом и новым обещанием; пришедший после резолва
// видит пустое обещание и начинает свою проверку.
func (checker *Checker) execute(ctx context.Context, active *promise) {
	verdict := checker.attempts(ctx)

	checker.mutex.Lock()

	active.verdict = verdict
	checker.active = nil
	checker.mutex.Unlock()

	checker.logf("ip check verdict %s ip=%q last error: %s", verdict.Kind, verdict.IP, verdict.LastError)

	close(active.done)
}

// attempts повторяет запрос по расписанию, пока не получит ответ или не выйдет бюджет.
// Бюджет исчерпан — вердикт KindBudget: отказ, а не пропуск.
func (checker *Checker) attempts(ctx context.Context) Verdict {
	clock := checker.config.Clock
	start := clock.Now()

	var lastError string

	for index := 0; ; index++ {
		body, err := checker.attempt(ctx)
		if err == nil {
			return checker.classify(body)
		}

		lastError = err.Error()
		checker.logf("ip check attempt %d failed: %s", index+1, lastError)

		delay := checker.retryDelay(index)
		if clock.Now().Sub(start)+delay >= checker.config.Budget {
			break
		}

		err = clock.Sleep(ctx, delay)
		if err != nil {
			lastError = err.Error()

			break
		}
	}

	return Verdict{Kind: KindBudget, IP: "", LastError: lastError, At: clock.Now()}
}

// attempt — одна попытка со своим таймаутом. Строка журнала на каждую попытку и есть
// доказательство совмещения: на пачку одновременных соединений их столько же, сколько
// запросов ушло к хосту проверки.
func (checker *Checker) attempt(ctx context.Context) (string, error) {
	checker.logf("ip check request to %s", checker.config.CheckURL)

	attemptCtx, cancel := context.WithTimeout(ctx, checker.config.AttemptTimeout)
	defer cancel()

	return checker.config.Fetch(attemptCtx, checker.config.CheckURL, checker.config.UpstreamProxy)
}

// classify переводит ответ хоста проверки в вердикт.
func (checker *Checker) classify(body string) Verdict {
	if body == checker.config.ExpectedIP {
		return Verdict{Kind: KindOK, IP: body, LastError: "", At: checker.config.Clock.Now()}
	}

	return Verdict{Kind: KindMismatch, IP: body, LastError: "", At: checker.config.Clock.Now()}
}

// retryDelay — пауза перед повтором: последняя из списка держится дальше.
func (checker *Checker) retryDelay(index int) time.Duration {
	delays := checker.config.RetryDelays
	if index < len(delays) {
		return delays[index]
	}

	return delays[len(delays)-1]
}

func (checker *Checker) logf(format string, args ...any) {
	if checker.config.Logf != nil {
		checker.config.Logf(format, args...)
	}
}

// NewChecker проверяет настройку и готовит сторожа.
func NewChecker(config Config) (*Checker, error) {
	switch {
	case config.ExpectedIP == "" || config.CheckURL == "":
		return nil, fmt.Errorf("%w: expected IP and check URL are required", ErrConfig)
	case config.AttemptTimeout <= 0 || config.Budget <= 0:
		return nil, fmt.Errorf("%w: timings must be positive", ErrConfig)
	case len(config.RetryDelays) == 0:
		return nil, fmt.Errorf("%w: retry delays are empty", ErrConfig)
	case config.Clock == nil || config.Fetch == nil:
		return nil, fmt.Errorf("%w: clock and fetch are required", ErrConfig)
	}

	ctx, cancel := context.WithCancel(context.Background())

	return &Checker{
		config: config,
		ctx:    ctx,
		cancel: cancel,
		mutex:  sync.Mutex{},
		active: nil,
	}, nil
}
