package install_test

import (
	"errors"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/kerbyfc/ipguard/internal/install"
)

// testAccount — SID владельца задачи в тестах планировщика.
const testAccount = "S-1-5-21-1111111111-2222222222-3333333333-1000"

// TestLaunchdEnsureWritesUnitAndRegisters: первой установкой запись кладётся в
// ~/Library/LaunchAgents и служба регистрируется в домене пользователя.
func TestLaunchdEnsureWritesUnitAndRegisters(t *testing.T) {
	t.Parallel()

	paths, log := macStand(t)

	service, err := install.PickService(install.GOOSDarwin, paths, log.Run)
	if err != nil {
		t.Fatalf("pick service: %v", err)
	}

	change, err := service.Ensure(paths.Binary)
	if err != nil {
		t.Fatalf("ensure: %v", err)
	}

	if !change.Done {
		t.Fatalf("ensure reported %q without doing anything", change.Note)
	}

	unit := readTestFile(t, paths.Unit)
	for _, part := range []string{install.Label, paths.Binary, "serve", "--service", paths.ServiceLog} {
		if !strings.Contains(unit, part) {
			t.Fatalf("plist has no %q:\n%s", part, unit)
		}
	}

	if !log.called("launchctl bootstrap gui/") {
		t.Fatalf("service was not registered: %v", log.calls)
	}

	if log.called("bootout") {
		t.Fatalf("unregistered service was booted out: %v", log.calls)
	}
}

// TestLaunchdEnsureConfirmsSettled: запись та же и служба зарегистрирована — launchd не
// трогается вовсе.
func TestLaunchdEnsureConfirmsSettled(t *testing.T) {
	t.Parallel()

	paths, log := macStand(t)

	service, err := install.PickService(install.GOOSDarwin, paths, log.Run)
	if err != nil {
		t.Fatalf("pick service: %v", err)
	}

	_, err = service.Ensure(paths.Binary)
	if err != nil {
		t.Fatalf("first ensure: %v", err)
	}

	log.calls = nil

	change, err := service.Ensure(paths.Binary)
	if err != nil {
		t.Fatalf("second ensure: %v", err)
	}

	if change.Done || !strings.Contains(change.Note, "already set up") {
		t.Fatalf("settled autostart reported %+v", change)
	}

	for _, call := range log.calls {
		if !strings.HasPrefix(call, "launchctl print") {
			t.Fatalf("settled autostart ran %q", call)
		}
	}

	if log.called("bootout") || log.called("bootstrap") {
		t.Fatalf("settled autostart reregistered the service: %v", log.calls)
	}
}

// TestLaunchdEnsureRereadsChangedUnit: сменившуюся запись launchd перечитывает только через
// снятие и постановку, поэтому идут обе команды.
func TestLaunchdEnsureRereadsChangedUnit(t *testing.T) {
	t.Parallel()

	paths, log := macStand(t)
	log.registered = true

	writeTestFile(t, paths.Unit, "<plist>старая запись</plist>")

	service, err := install.PickService(install.GOOSDarwin, paths, log.Run)
	if err != nil {
		t.Fatalf("pick service: %v", err)
	}

	change, err := service.Ensure(paths.Binary)
	if err != nil {
		t.Fatalf("ensure: %v", err)
	}

	if !change.Done {
		t.Fatalf("changed unit reported %+v", change)
	}

	if !strings.Contains(readTestFile(t, paths.Unit), paths.Binary) {
		t.Fatal("unit was not rewritten")
	}

	bootout := indexOfCall(log.calls, "bootout")
	bootstrap := indexOfCall(log.calls, "bootstrap")

	if bootout < 0 || bootstrap < 0 || bootout > bootstrap {
		t.Fatalf("bootout must precede bootstrap: %v", log.calls)
	}
}

// TestLaunchdEnsureWaitsForBootoutAndRetriesBootstrap: bootout асинхронный, и bootstrap
// сразу после него launchd отвергает с Input/output error. Установка ждёт, пока домен
// отпустит ярлык, и повторяет bootstrap.
func TestLaunchdEnsureWaitsForBootoutAndRetriesBootstrap(t *testing.T) {
	t.Parallel()

	paths, log := macStand(t)
	log.registered = true
	log.bootoutLinger = 2
	log.bootstrapFails = 1

	writeTestFile(t, paths.Unit, "<plist>старая запись</plist>")

	service := pausedLaunchd(t, paths, log)

	change, err := service.Ensure(paths.Binary)
	if err != nil {
		t.Fatalf("ensure: %v", err)
	}

	if !change.Done {
		t.Fatalf("changed unit reported %+v", change)
	}

	if log.bootstraps != 2 {
		t.Fatalf("bootstrap attempts %d, want 2: %v", log.bootstraps, log.calls)
	}

	bootout := indexOfCall(log.calls, "bootout")
	bootstrap := indexOfCall(log.calls, "bootstrap")

	if bootout < 0 || bootstrap < 0 || bootout > bootstrap {
		t.Fatalf("bootout must precede bootstrap: %v", log.calls)
	}

	prints := 0

	for _, call := range log.calls[bootout+1 : bootstrap] {
		if strings.HasPrefix(call, "launchctl print") {
			prints++
		}
	}

	if prints != log.bootoutLinger+1 {
		t.Fatalf(
			"domain checked %d times before bootstrap, want %d: %v",
			prints, log.bootoutLinger+1, log.calls,
		)
	}
}

// TestLaunchdEnsureReturnsBootstrapErrorAfterAttempts: домен так и не отпустил службу —
// bootstrap повторяется ограниченное число раз, и наружу уходит последний отказ launchctl.
func TestLaunchdEnsureReturnsBootstrapErrorAfterAttempts(t *testing.T) {
	t.Parallel()

	paths, log := macStand(t)
	log.registered = true
	log.bootoutLinger = 1 << 20
	log.bootstrapFails = 1 << 20

	writeTestFile(t, paths.Unit, "<plist>старая запись</plist>")

	service := pausedLaunchd(t, paths, log)

	_, err := service.Ensure(paths.Binary)
	if err == nil {
		t.Fatal("ensure succeeded, want a bootstrap error")
	}

	if !errors.Is(err, errBootstrap) {
		t.Fatalf("ensure gave %v, want the launchctl bootstrap error", err)
	}

	for _, part := range []string{"launchctl", "Bootstrap failed", "Input/output error"} {
		if !strings.Contains(err.Error(), part) {
			t.Fatalf("error %q has no %q", err, part)
		}
	}

	if log.bootstraps < 2 {
		t.Fatalf("bootstrap was tried %d times, want retries", log.bootstraps)
	}
}

// TestLaunchdBootstrapStopsOnPermanentError: постоянный отказ launchctl не повторяется —
// иначе негодная запись растягивала бы установку на всё окно гонки.
func TestLaunchdBootstrapStopsOnPermanentError(t *testing.T) {
	t.Parallel()

	paths, log := macStand(t)
	log.registered = true
	log.bootstrapFails = 1 << 20
	log.bootstrapError = errPermanentBootstrap

	writeTestFile(t, paths.Unit, "<plist>старая запись</plist>")

	service := pausedLaunchd(t, paths, log)

	_, err := service.Ensure(paths.Binary)
	if err == nil {
		t.Fatal("ensure succeeded, want the permanent launchctl error")
	}

	if log.bootstraps != 1 {
		t.Fatalf("bootstrap was tried %d times on a permanent error, want 1", log.bootstraps)
	}
}

// TestLaunchdEnsureRejectsBrokenPlistBeforeLaunchctl: негодный plist launchctl отвергает тем же
// Input/output error, что и гонку, поэтому запись проверяется до команд домена.
func TestLaunchdEnsureRejectsBrokenPlistBeforeLaunchctl(t *testing.T) {
	t.Parallel()

	paths, log := macStand(t)
	log.plistErr = errBrokenPlist

	service := pausedLaunchd(t, paths, log)

	_, err := service.Ensure(paths.Binary)
	if err == nil {
		t.Fatal("ensure accepted a broken plist")
	}

	if !errors.Is(err, install.ErrInstall) || !strings.Contains(err.Error(), "plist") {
		t.Fatalf("ensure gave %v, want a plist install error", err)
	}

	if log.called("bootstrap") || log.called("bootout") {
		t.Fatalf("launchctl was called on a broken plist: %v", log.calls)
	}
}

// TestLaunchdEnsureTreatsAbsentServiceAsBootedOut: «No such process» — службы уже нет, это
// успех снятия, а не отказ установки.
func TestLaunchdEnsureTreatsAbsentServiceAsBootedOut(t *testing.T) {
	t.Parallel()

	paths, log := macStand(t)
	log.registered = true
	log.bootoutErrors = []error{
		errNoSuchProcess,
	}

	writeTestFile(t, paths.Unit, "<plist>старая запись</plist>")

	service := pausedLaunchd(t, paths, log)

	change, err := service.Ensure(paths.Binary)
	if err != nil {
		t.Fatalf("ensure: %v", err)
	}

	if !change.Done || !log.called("bootstrap") {
		t.Fatalf("ensure reported %+v, calls %v", change, log.calls)
	}
}

// TestLaunchdBootoutRetriesWhileInProgress: «Operation now in progress» — временный ответ,
// его ждут и повторяют, а не обрывают установку.
func TestLaunchdBootoutRetriesWhileInProgress(t *testing.T) {
	t.Parallel()

	paths, log := macStand(t)
	log.registered = true
	log.bootoutErrors = []error{
		errInProgress,
		nil,
	}

	writeTestFile(t, paths.Unit, "<plist>старая запись</plist>")

	service := pausedLaunchd(t, paths, log)

	_, err := service.Ensure(paths.Binary)
	if err != nil {
		t.Fatalf("ensure: %v", err)
	}

	bootouts := 0

	for _, call := range log.calls {
		if strings.Contains(call, "launchctl bootout") {
			bootouts++
		}
	}

	if bootouts != 2 {
		t.Fatalf("bootout was called %d times, want 2: %v", bootouts, log.calls)
	}
}

// TestLaunchdStartKickstartsLiveService: запуск поднимает вышедшую службу и не трогает
// идущую — иначе повторная установка рвала бы живой туннель.
func TestLaunchdStartKickstartsLiveService(t *testing.T) {
	t.Parallel()

	paths, log := macStand(t)

	service, err := install.PickService(install.GOOSDarwin, paths, log.Run)
	if err != nil {
		t.Fatalf("pick service: %v", err)
	}

	err = service.Start()
	if err != nil {
		t.Fatalf("start: %v", err)
	}

	if !log.called("launchctl kickstart gui/") {
		t.Fatalf("service was not started: %v", log.calls)
	}

	if log.called("kickstart -k") {
		t.Fatalf("start killed a live service: %v", log.calls)
	}
}

// TestLaunchdRestartKickstarts: новый бинарник подхватывается только перезапуском процесса.
func TestLaunchdRestartKickstarts(t *testing.T) {
	t.Parallel()

	paths, log := macStand(t)

	service, err := install.PickService(install.GOOSDarwin, paths, log.Run)
	if err != nil {
		t.Fatalf("pick service: %v", err)
	}

	err = service.Restart()
	if err != nil {
		t.Fatalf("restart: %v", err)
	}

	if !log.called("launchctl kickstart -k gui/") {
		t.Fatalf("service was not restarted: %v", log.calls)
	}
}

// TestLaunchdRemoveTakesServiceAndUnit: снятие убирает и службу, и запись; снимать нечего —
// это подтверждение, а не ошибка.
func TestLaunchdRemoveTakesServiceAndUnit(t *testing.T) {
	t.Parallel()

	paths, log := macStand(t)
	log.registered = true

	writeTestFile(t, paths.Unit, "<plist>запись</plist>")

	service, err := install.PickService(install.GOOSDarwin, paths, log.Run)
	if err != nil {
		t.Fatalf("pick service: %v", err)
	}

	change, err := service.Remove()
	if err != nil {
		t.Fatalf("remove: %v", err)
	}

	if !change.Done || !log.called("bootout") {
		t.Fatalf("remove reported %+v, calls %v", change, log.calls)
	}

	_, err = os.Stat(paths.Unit)
	if !os.IsNotExist(err) {
		t.Fatalf("stat unit gave %v, want it removed", err)
	}

	log.registered = false

	change, err = service.Remove()
	if err != nil {
		t.Fatalf("second remove: %v", err)
	}

	if change.Done || !strings.Contains(change.Note, "there was no autostart") {
		t.Fatalf("second remove reported %+v", change)
	}
}

// TestSchtasksEnsureCreatesUTF16Task: планировщик Windows принимает только UTF-16 с BOM,
// поэтому XML задачи пишется именно так.
func TestSchtasksEnsureCreatesUTF16Task(t *testing.T) {
	t.Parallel()

	paths, log := windowsStand(t)
	log.queryFails = true

	service := windowsService(paths, log)

	change, err := service.Ensure(paths.Binary)
	if err != nil {
		t.Fatalf("ensure: %v", err)
	}

	if !change.Done || !log.called("schtasks /Create") {
		t.Fatalf("ensure reported %+v, calls %v", change, log.calls)
	}

	if len(log.createdXML) < 2 || log.createdXML[0] != 0xFF || log.createdXML[1] != 0xFE {
		t.Fatalf("task XML is not UTF-16 with BOM: %v", log.createdXML[:min(4, len(log.createdXML))])
	}

	unit := decodeTestUTF16(log.createdXML)
	parts := []string{
		"<Command>" + paths.Binary + "</Command>",
		"<Arguments>serve --service</Arguments>",
		"LogonTrigger",
		"ipguard-unit:",
	}

	for _, part := range parts {
		if !strings.Contains(unit, part) {
			t.Fatalf("task XML has no %q:\n%s", part, unit)
		}
	}
}

// TestSchtasksEnsureOwnsTaskByAccount: запись называет владельца и в триггере входа, и в
// учётной записи запуска. Запись без владельца значит «вход любого пользователя», а такую
// задачу планировщик отдаёт только администратору: обычная установка получает от него
// `Access is denied`.
func TestSchtasksEnsureOwnsTaskByAccount(t *testing.T) {
	t.Parallel()

	paths, log := windowsStand(t)
	log.queryFails = true

	service := windowsService(paths, log)

	_, err := service.Ensure(paths.Binary)
	if err != nil {
		t.Fatalf("ensure: %v", err)
	}

	unit := decodeTestUTF16(log.createdXML)
	parts := []string{
		"<LogonTrigger>\n      <Enabled>true</Enabled>\n      <UserId>" + testAccount + "</UserId>",
		"<Principal id=\"Author\">\n      <UserId>" + testAccount + "</UserId>",
	}

	for _, part := range parts {
		if !strings.Contains(unit, part) {
			t.Fatalf("task XML has no %q:\n%s", part, unit)
		}
	}
}

// TestSchtasksEnsureRejectsUnknownAccount: владелец задачи неизвестен — отказ, а не запись
// «вход любого пользователя», которую планировщик всё равно не примет.
func TestSchtasksEnsureRejectsUnknownAccount(t *testing.T) {
	t.Parallel()

	paths, log := windowsStand(t)
	log.queryFails = true

	service := install.NewSchtasksForTest(paths, log.Run, "")

	_, err := service.Ensure(paths.Binary)
	if !errors.Is(err, install.ErrInstall) {
		t.Fatalf("ensure gave %v, want an install error", err)
	}

	if log.called("/Create") {
		t.Fatalf("task was created without an owner: %v", log.calls)
	}
}

// TestSchtasksEnsureConfirmsSameTask: в планировщике лежит та же запись — он не трогается.
// Сверяется отпечаток записи, который она несёт в `<Description>`: XML из `/Query`
// планировщик нормализует, и побайтово его сравнивать нельзя.
func TestSchtasksEnsureConfirmsSameTask(t *testing.T) {
	t.Parallel()

	paths, log := windowsStand(t)
	log.queryFails = true

	service := windowsService(paths, log)

	_, err := service.Ensure(paths.Binary)
	if err != nil {
		t.Fatalf("first ensure: %v", err)
	}

	// Планировщик отдаёт запись переформатированной, но отпечаток — как есть.
	log.queryXML = encodeTestUTF16(strings.ReplaceAll(decodeTestUTF16(log.createdXML), "\n  ", "\n\t"))
	log.queryFails = false
	log.calls = nil

	change, err := service.Ensure(paths.Binary)
	if err != nil {
		t.Fatalf("second ensure: %v", err)
	}

	if change.Done || !strings.Contains(change.Note, "already set up") {
		t.Fatalf("settled task reported %+v", change)
	}

	if log.called("/Create") {
		t.Fatalf("settled task was recreated: %v", log.calls)
	}
}

// TestSchtasksEnsureRewritesChangedUnit: правка шаблона доезжает до уже установленной машины.
// Прежняя задача запускает тот же бинарник, но остальная запись другая — она переписывается,
// иначе шаг «автозапуск» перестал бы отвечать на вопрос «желаемое равно фактическому».
func TestSchtasksEnsureRewritesChangedUnit(t *testing.T) {
	t.Parallel()

	paths, log := windowsStand(t)
	log.queryXML = encodeTestUTF16(
		`<Task><RegistrationInfo><Description>claude-ipguard [ipguard-unit:0000000000000000]` +
			`</Description></RegistrationInfo><Settings><ExecutionTimeLimit>PT72H</ExecutionTimeLimit>` +
			`</Settings><Actions><Exec><Command>` + paths.Binary + `</Command></Exec></Actions></Task>`,
	)

	service := windowsService(paths, log)

	change, err := service.Ensure(paths.Binary)
	if err != nil {
		t.Fatalf("ensure: %v", err)
	}

	if !change.Done || !log.called("schtasks /Create") {
		t.Fatalf("changed unit reported %+v, calls %v", change, log.calls)
	}
}

// TestSchtasksStartRunsTask: `/Create` задачу только регистрирует, процесс поднимает триггер
// входа в систему, поэтому запуск задачи — отдельная команда планировщику. Идущий экземпляр
// запуск не трогает: `/Run` рядом с живым процессом планировщик отбрасывает сам, а установка
// не рвёт живой туннель остановкой.
func TestSchtasksStartRunsTask(t *testing.T) {
	t.Parallel()

	paths, log := windowsStand(t)

	service := windowsService(paths, log)

	err := service.Start()
	if err != nil {
		t.Fatalf("start: %v", err)
	}

	if !log.called("schtasks /Run") {
		t.Fatalf("task was not started: %v", log.calls)
	}

	if log.called("/End") {
		t.Fatalf("start stopped a live task: %v", log.calls)
	}
}

// TestSchtasksRestartWaitsForStoppedProcess: `/End` асинхронный, а `/Run` рядом с ещё живым
// экземпляром планировщик отбрасывает молча (`MultipleInstancesPolicy: IgnoreNew`) — служба
// осталась бы снятой. Перезапуск ждёт, пока процесс уйдёт, и только потом поднимает задачу.
func TestSchtasksRestartWaitsForStoppedProcess(t *testing.T) {
	t.Parallel()

	paths, log := windowsStand(t)
	log.aliveProcesses = 2

	service := windowsService(paths, log)

	err := service.Restart()
	if err != nil {
		t.Fatalf("restart: %v", err)
	}

	end := indexOfCall(log.calls, "/End")
	run := indexOfCall(log.calls, "/Run")

	if end < 0 || run < 0 || end > run {
		t.Fatalf("/End must precede /Run: %v", log.calls)
	}

	polls := 0

	for _, call := range log.calls[end+1 : run] {
		if strings.HasPrefix(call, "tasklist") {
			polls++
		}
	}

	if polls != 3 {
		t.Fatalf("process checked %d times before /Run, want 3: %v", polls, log.calls)
	}
}

// TestSchtasksRemoveStopsAndDeletes: снятие останавливает и удаляет задачу; задачи нет — это
// подтверждение.
func TestSchtasksRemoveStopsAndDeletes(t *testing.T) {
	t.Parallel()

	paths, log := windowsStand(t)

	service := windowsService(paths, log)

	change, err := service.Remove()
	if err != nil {
		t.Fatalf("remove: %v", err)
	}

	if !change.Done || !log.called("/End") || !log.called("/Delete") {
		t.Fatalf("remove reported %+v, calls %v", change, log.calls)
	}

	log.queryFails = true
	log.calls = nil

	change, err = service.Remove()
	if err != nil {
		t.Fatalf("second remove: %v", err)
	}

	if change.Done || !strings.Contains(change.Note, "there was no autostart") {
		t.Fatalf("second remove reported %+v", change)
	}

	if log.called("/Delete") {
		t.Fatalf("absent task was deleted: %v", log.calls)
	}
}

// TestPickServiceRejectsOtherOS: ОС без автозапуска — отказ, а не установка без автозапуска.
func TestPickServiceRejectsOtherOS(t *testing.T) {
	t.Parallel()

	paths, log := macStand(t)

	_, err := install.PickService("linux", paths, log.Run)
	if !errors.Is(err, install.ErrInstall) {
		t.Fatalf("pick service for linux gave %v, want an install error", err)
	}
}

// macStand — адреса установки macOS и подложный launchctl.
func macStand(t *testing.T) (install.Paths, *commandLog) {
	t.Helper()

	return osStand(t, install.GOOSDarwin)
}

// windowsStand — адреса установки Windows и подложный schtasks.
func windowsStand(t *testing.T) (install.Paths, *commandLog) {
	t.Helper()

	return osStand(t, install.GOOSWindows)
}

// windowsService — планировщик Windows с подложными командами и заданным владельцем задачи:
// SID настоящей машины в запись теста не попадает.
func windowsService(paths install.Paths, log *commandLog) install.Service {
	return install.NewSchtasksForTest(paths, log.Run, testAccount)
}

// osStand — адреса установки для ОС goos в своей домашней папке и подложные команды ОС.
func osStand(t *testing.T, goos string) (install.Paths, *commandLog) {
	t.Helper()

	paths, err := install.NewPaths(goos, t.TempDir())
	if err != nil {
		t.Fatalf("paths for %s: %v", goos, err)
	}

	return paths, &commandLog{
		calls:          nil,
		createdXML:     nil,
		queryXML:       "",
		registered:     false,
		queryFails:     false,
		bootoutLinger:  0,
		lingering:      0,
		bootstrapFails: 0,
		bootstrapError: nil,
		bootstraps:     0,
		bootoutErrors:  nil,
		plistErr:       nil,
		aliveProcesses: 0,
	}
}

// pausedLaunchd — launchd с подложным запуском команд и паузой без сна.
func pausedLaunchd(t *testing.T, paths install.Paths, log *commandLog) install.Service {
	t.Helper()

	return install.NewLaunchdForTest(paths, log.Run, "501", func(time.Duration) {})
}

// indexOfCall — место вызова с подстрокой part в журнале вызовов.
func indexOfCall(calls []string, part string) int {
	for index, call := range calls {
		if strings.Contains(call, part) {
			return index
		}
	}

	return -1
}
