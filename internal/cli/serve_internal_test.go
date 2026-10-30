package cli

import (
	"fmt"
	"strings"
	"testing"
)

// TestLogGuardSummary: при старте в журнал идёт одна строка о границе — вердикта ждёт любой
// хост, кроме исключений, — и о числе накопленного, без перечисления списков.
func TestLogGuardSummary(t *testing.T) {
	t.Parallel()

	var lines []string

	logGuardSummary(func(format string, args ...any) {
		lines = append(lines, fmt.Sprintf(format, args...))
	}, 3, 25)

	if len(lines) != 1 {
		t.Fatalf("log lines %d, want one", len(lines))
	}

	if !strings.Contains(lines[0], "except 3 unguarded patterns") || !strings.Contains(lines[0], "25 hosts") {
		t.Fatalf("log line %q names neither the whitelist nor the recorded hosts", lines[0])
	}
}
