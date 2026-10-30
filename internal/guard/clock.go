package guard

import (
	"context"
	"fmt"
	"time"
)

// Clock — время сторожа; тесты подменяют его, чтобы проверить расписание и бюджет без живого сна.
type Clock interface {
	Now() time.Time
	Sleep(ctx context.Context, delay time.Duration) error
}

type realClock struct{}

func (realClock) Now() time.Time {
	return time.Now()
}

func (realClock) Sleep(ctx context.Context, delay time.Duration) error {
	timer := time.NewTimer(delay)
	defer timer.Stop()

	select {
	case <-timer.C:
		return nil
	case <-ctx.Done():
		return fmt.Errorf("%w: %w", ErrCanceled, ctx.Err())
	}
}

// RealClock — живое время.
func RealClock() Clock {
	return realClock{}
}
