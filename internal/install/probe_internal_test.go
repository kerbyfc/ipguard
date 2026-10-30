package install

import (
	"testing"
	"time"

	"github.com/kerbyfc/ipguard/internal/config"
)

// TestProbeTimeoutOutlivesAttempt: проба установки ждёт дольше одной попытки проверки при
// любой настройке attempt_timeout, иначе она отчиталась бы отказом о живой службе.
func TestProbeTimeoutOutlivesAttempt(t *testing.T) {
	t.Parallel()

	settings := config.Defaults()
	if probeTimeout(settings) <= settings.AttemptTimeout {
		t.Fatalf(
			"probe timeout %s is not longer than the default attempt %s",
			probeTimeout(settings), settings.AttemptTimeout,
		)
	}

	settings.AttemptTimeout = 2 * time.Minute
	if probeTimeout(settings) <= settings.AttemptTimeout {
		t.Fatalf(
			"probe timeout %s is not longer than a custom attempt %s",
			probeTimeout(settings), settings.AttemptTimeout,
		)
	}
}
