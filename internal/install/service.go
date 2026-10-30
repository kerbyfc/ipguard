package install

import (
	"bytes"
	"crypto/sha256"
	"embed"
	"encoding/hex"
	"encoding/xml"
	"fmt"
	"os"
	"os/user"
	"path/filepath"
	"strconv"
	"strings"
	"text/template"
	"time"
	"unicode/utf16"
)

const (
	// taskFingerprintMark — метка отпечатка записи в `<Description>` задачи планировщика: по
	// ней отпечаток находится в XML, который отдаёт `schtasks /Query`.
	taskFingerprintMark = "ipguard-unit:"
	// fingerprintLength — сколько знаков отпечатка идёт в запись: половины sha256 хватает,
	// чтобы правка шаблона не совпала с прежней записью.
	fingerprintLength = 32
	// bootoutPolls — сколько раз проверять домен после `bootout`: сам он асинхронный, и
	// `bootstrap` рядом с ещё живым ярлыком launchd отвергает с Input/output error. Это
	// только предварительная проверка; в прогоне владельца домен был свободен сразу.
	bootoutPolls = 100
	// bootoutPoll — пауза между проверками домена.
	bootoutPoll = 100 * time.Millisecond
	// bootoutAttempts — сколько раз повторять `bootout` на «Operation now in progress».
	bootoutAttempts = 10
	// bootstrapBudget — окно гонки: в прогоне владельца `bootstrap` отказал в 12:48, а руками
	// прошёл примерно через две минуты. Цифра взята из этого замера, не из воздуха.
	bootstrapBudget = 2 * time.Minute
	// bootstrapPause — пауза между попытками `bootstrap` внутри окна гонки.
	bootstrapPause = time.Second
	// bootstrapAttempts — попыток в окне: само окно и задаёт терпение установки.
	bootstrapAttempts = int(bootstrapBudget / bootstrapPause)
	// endPolls — сколько раз проверять, ушёл ли процесс остановленной задачи: `/End`
	// асинхронный, а `/Run` рядом с ещё живым экземпляром планировщик отбрасывает молча
	// (`MultipleInstancesPolicy: IgnoreNew`), и служба осталась бы снятой.
	endPolls = 100
	// endPoll — пауза между проверками процесса остановленной задачи.
	endPoll = 100 * time.Millisecond
)

//go:embed templates/launchd.plist.tmpl templates/schtasks.xml.tmpl
var unitTemplates embed.FS

// Change — итог шага установки: Done — что-то изменилось, Note — строка отчёта для владельца.
type Change struct {
	Done bool
	Note string
}

// Runner запускает команду ОС и отдаёт её вывод: тесты подменяют его и не трогают launchd
// и планировщик настоящей машины.
type Runner func(name string, args ...string) (string, error)

// Service — автозапуск ОС: приведение записи к нынешнему бинарнику, запуск, перезапуск и
// снятие.
type Service interface {
	// Describe — имя механизма автозапуска для отчёта.
	Describe() string
	// Ensure приводит автозапуск к бинарнику binary; уже настроенный не переделывается.
	// Запись сама процесс не поднимает: это делает Start.
	Ensure(binary string) (Change, error)
	// Start поднимает службу: после успешного вызова её процесс идёт. Уже идущий процесс
	// launchd не трогает, планировщик Windows поднимает заново — состояние задачи он
	// называет только локализованной строкой.
	Start() error
	// Restart перезапускает службу вместе с процессом: новый бинарник подхватывается только
	// так.
	Restart() error
	// Remove снимает автозапуск и останавливает службу.
	Remove() (Change, error)
	// Installed — заведён ли автозапуск. По нему команда правки настроек решает,
	// перезапускать службу или сказать, что сторож ещё не установлен.
	Installed() (bool, error)
}

// launchd — автозапуск macOS: файл записи в ~/Library/LaunchAgents и служба в домене
// gui/<uid>.
type launchd struct {
	paths  Paths
	runner Runner
	pause  func(time.Duration)
	uid    string
}

// Describe — имя механизма автозапуска для отчёта.
func (service launchd) Describe() string {
	return "launchd (gui/" + service.uid + "/" + Label + ")"
}

// Ensure пишет запись и регистрирует службу. Запись уже та же и служба зарегистрирована —
// ничего не делается.
func (service launchd) Ensure(binary string) (Change, error) {
	unit, err := renderLaunchd(binary, service.paths)
	if err != nil {
		return Change{Done: false, Note: ""}, err
	}

	same, err := fileHasContent(service.paths.Unit, unit)
	if err != nil {
		return Change{Done: false, Note: ""}, err
	}

	registered := service.registered()

	if same && registered {
		return Change{Done: false, Note: "already set up, " + service.paths.Unit}, nil
	}

	err = service.reload(unit, same, registered)
	if err != nil {
		return Change{Done: false, Note: ""}, err
	}

	note := "unit updated and the service registered, " + service.paths.Unit
	if same {
		note = "the service registered, " + service.paths.Unit
	}

	return Change{Done: true, Note: note}, nil
}

// reload кладёт сменившуюся запись и регистрирует службу: правку записи launchd перечитывает
// только через снятие и постановку.
func (service launchd) reload(unit []byte, same, registered bool) error {
	if !same {
		err := writeFile(service.paths.Unit, unit, unitMode)
		if err != nil {
			return err
		}
	}

	err := service.validateUnit()
	if err != nil {
		return err
	}

	if registered {
		err = service.bootout()
		if err != nil {
			return err
		}

		service.awaitBootout()
	}

	return service.bootstrap()
}

// validateUnit проверяет запись до launchctl: негодный plist launchd отвергает тем же
// Input/output error, что и гонку, и повторять его всё окно незачем.
func (service launchd) validateUnit() error {
	output, err := service.runner("plutil", "-lint", service.paths.Unit)
	if err != nil {
		return fmt.Errorf(
			"%w: plist %s is invalid: %w: %s",
			ErrInstall, service.paths.Unit, err, strings.TrimSpace(output),
		)
	}

	return nil
}

// bootout снимает службу. «No such process» — успех: службы и так нет. «Operation now in
// progress» — ответ, который проходит сам, поэтому его ждём и повторяем ограниченно.
func (service launchd) bootout() error {
	var last error

	for attempt := range bootoutAttempts {
		output, err := service.runner("launchctl", "bootout", service.target())
		if err == nil {
			return nil
		}

		text := strings.ToLower(output + " " + err.Error())

		switch {
		case strings.Contains(text, "no such process"):
			return nil
		case strings.Contains(text, "operation now in progress"):
			last = err

			if attempt+1 < bootoutAttempts {
				service.pause(bootoutPoll)
			}
		default:
			return err
		}
	}

	return last
}

// awaitBootout ждёт, пока домен отпустит снятую службу: `bootout` асинхронный, и
// `bootstrap` рядом с ещё живым ярлыком launchd отвергает с Input/output error. Ожидание
// ограничено — дальше решает ответ самого `bootstrap`.
func (service launchd) awaitBootout() {
	for range bootoutPolls {
		if !service.registered() {
			return
		}

		service.pause(bootoutPoll)
	}
}

// bootstrap регистрирует службу и повторяет попытку на остаточной гонке. Повтор идёт только
// на известный текст гонки, а не на любой отказ: постоянная ошибка выходит сразу, не растягивая
// установку на всё окно. Последний отказ уходит наружу как есть, с текстом launchctl.
func (service launchd) bootstrap() error {
	var last error

	for attempt := range bootstrapAttempts {
		_, err := service.runner("launchctl", "bootstrap", "gui/"+service.uid, service.paths.Unit)
		if err == nil {
			return nil
		}

		last = err

		if !bootstrapRace(err) {
			return err
		}

		if attempt+1 < bootstrapAttempts {
			service.pause(bootstrapPause)
		}
	}

	return last
}

// Start поднимает процесс службы. `kickstart` без `-k` идущий процесс не трогает, поэтому
// повторная установка живой туннель не рвёт.
func (service launchd) Start() error {
	_, err := service.runner("launchctl", "kickstart", service.target())

	return err
}

// Restart перезапускает службу вместе с её процессом.
func (service launchd) Restart() error {
	_, err := service.runner("launchctl", "kickstart", "-k", service.target())

	return err
}

// Remove снимает службу и удаляет запись.
func (service launchd) Remove() (Change, error) {
	changed := false

	if service.registered() {
		err := service.bootout()
		if err != nil {
			return Change{Done: false, Note: ""}, err
		}

		changed = true
	}

	removed, err := removeFile(service.paths.Unit)
	if err != nil {
		return Change{Done: false, Note: ""}, err
	}

	if !changed && !removed {
		return Change{Done: false, Note: "there was no autostart"}, nil
	}

	return Change{Done: true, Note: "removed, " + service.paths.Unit}, nil
}

// Installed — есть ли файл записи автозапуска. Файл, а не регистрация: служба могла выйти,
// но установленной от этого быть не перестала.
func (service launchd) Installed() (bool, error) {
	_, err := os.Stat(service.paths.Unit)

	switch {
	case err == nil:
		return true, nil
	case os.IsNotExist(err):
		return false, nil
	default:
		return false, fmt.Errorf("%w: %s: %w", ErrInstall, service.paths.Unit, err)
	}
}

// registered — зарегистрирована ли служба в домене пользователя.
func (service launchd) registered() bool {
	_, err := service.runner("launchctl", "print", service.target())

	return err == nil
}

// target — адрес службы в домене пользователя.
func (service launchd) target() string {
	return "gui/" + service.uid + "/" + Label
}

// schtasks — автозапуск Windows: задача планировщика с триггером входа в систему. Своего
// файла у записи нет, она живёт в планировщике, а XML ему отдаётся разово.
type schtasks struct {
	paths  Paths
	runner Runner
	// account — SID владельца задачи: он идёт и в триггер входа, и в учётную запись
	// запуска. Без него запись значит «вход любого пользователя», а такую задачу
	// планировщик отдаёт только администратору и отказывает обычному запуску
	// `Access is denied`.
	account string
	// pause — ожидание между проверками процесса остановленной задачи.
	pause func(time.Duration)
}

// Describe — имя механизма автозапуска для отчёта.
func (service schtasks) Describe() string {
	return "Windows Task Scheduler (" + TaskName + ")"
}

// Ensure создаёт задачу планировщика. Задача уже несёт отпечаток нынешней записи — ничего не
// делается; разошлась любым полем — записывается заново.
func (service schtasks) Ensure(binary string) (Change, error) {
	unit, stamp, err := renderTask(binary, service.account)
	if err != nil {
		return Change{Done: false, Note: ""}, err
	}

	current, queryErr := service.runner("schtasks", "/Query", "/TN", TaskName, "/XML")
	if queryErr == nil && strings.Contains(decodeUTF16(current), stamp) {
		return Change{Done: false, Note: "already set up, the task " + TaskName}, nil
	}

	// Имя файла записи разовое: за одно имя в TEMP спорили бы одновременные запуски.
	reserved, err := os.CreateTemp("", TaskName+"-*.xml")
	if err != nil {
		return Change{Done: false, Note: ""}, fmt.Errorf("%w: %s: %w", ErrInstall, os.TempDir(), err)
	}

	file := reserved.Name()

	defer func() { _, _ = removeFile(file) }()

	err = reserved.Close()
	if err != nil {
		return Change{Done: false, Note: ""}, fmt.Errorf("%w: %s: %w", ErrInstall, file, err)
	}

	err = writeFile(file, unit, unitMode)
	if err != nil {
		return Change{Done: false, Note: ""}, err
	}

	_, err = service.runner("schtasks", "/Create", "/TN", TaskName, "/XML", file, "/F")
	if err != nil {
		return Change{Done: false, Note: ""}, err
	}

	return Change{Done: true, Note: "created the task " + TaskName}, nil
}

// Start поднимает задачу: `/Create` её только регистрирует, а процесс поднимает триггер
// входа в систему. Идущий процесс остаётся как есть — `MultipleInstancesPolicy: IgnoreNew`
// значит, что `/Run` рядом с живым экземпляром ничего не делает, а вышедшую службу он
// поднимает. Так повторная установка не рвёт живой туннель.
func (service schtasks) Start() error {
	_, err := service.runner("schtasks", "/Run", "/TN", TaskName)

	return err
}

// Restart перезапускает задачу: остановка, ожидание ушедшего процесса и запуск. Остановка не
// идущей задачи — не ошибка установки, поэтому её код игнорируется; значение имеет только
// запуск.
func (service schtasks) Restart() error {
	_, _ = service.runner("schtasks", "/End", "/TN", TaskName)

	service.awaitProcessGone()

	_, err := service.runner("schtasks", "/Run", "/TN", TaskName)

	return err
}

// awaitProcessGone ждёт, пока остановленная задача отпустит свой процесс: `/End` асинхронный,
// и `/Run` рядом с ещё живым экземпляром планировщик отбрасывает молча. Процесс виден по
// имени образа — единственное, что в выводе планировщика и `tasklist` не локализовано.
// Ожидание ограничено: дальше решает проба живого сервиса.
func (service schtasks) awaitProcessGone() {
	image := filepath.Base(service.paths.Binary)

	for range endPolls {
		output, err := service.runner("tasklist", "/FO", "CSV", "/NH", "/FI", "IMAGENAME eq "+image)
		if err != nil || !strings.Contains(output, image) {
			return
		}

		service.pause(endPoll)
	}
}

// Remove останавливает и удаляет задачу.
func (service schtasks) Remove() (Change, error) {
	_, err := service.runner("schtasks", "/Query", "/TN", TaskName)
	if err != nil {
		// Задачи нет — снимать нечего, и это подтверждение шага, а не отказ.
		return Change{Done: false, Note: "there was no autostart"}, nil //nolint:nilerr // задачи нет
	}

	_, _ = service.runner("schtasks", "/End", "/TN", TaskName)

	_, err = service.runner("schtasks", "/Delete", "/TN", TaskName, "/F")
	if err != nil {
		return Change{Done: false, Note: ""}, err
	}

	return Change{Done: true, Note: "removed the task " + TaskName}, nil
}

// Installed — есть ли задача в планировщике. Планировщик отвечает кодом, а не строкой,
// поэтому его отказ и значит «задачи нет».
func (service schtasks) Installed() (bool, error) {
	_, err := service.runner("schtasks", "/Query", "/TN", TaskName)

	return err == nil, nil
}

// newSchtasks — автозапуск через планировщик задач Windows.
func newSchtasks(paths Paths, runner Runner, account string, pause func(time.Duration)) schtasks {
	return schtasks{paths: paths, runner: runner, account: account, pause: pause}
}

// currentAccount — SID нынешнего пользователя: владелец задачи планировщика. SID, а не имя:
// имя учётной записи планировщик отдаёт локализованной строкой, а записи нужен адрес, по
// которому он и сверяет владельца.
func currentAccount() (string, error) {
	account, err := user.Current()
	if err != nil {
		return "", fmt.Errorf("%w: current user is unknown: %w", ErrInstall, err)
	}

	if account.Uid == "" {
		return "", fmt.Errorf("%w: current user has no SID", ErrInstall)
	}

	return account.Uid, nil
}

// bootstrapRace — похож ли отказ на гонку домена. launchctl отдаёт код 5 и на негодный plist,
// поэтому повторяется только текст, которым он называет именно гонку.
func bootstrapRace(err error) bool {
	text := strings.ToLower(err.Error())

	return strings.Contains(text, "input/output error") ||
		strings.Contains(text, "operation now in progress")
}

// ExecRunner — настоящий запуск команд ОС.
func ExecRunner(name string, args ...string) (string, error) {
	output, err := runCommand(name, args)
	if err != nil {
		return output, fmt.Errorf(
			"%w: %s %s: %w: %s",
			ErrInstall, name, strings.Join(args, " "), err, strings.TrimSpace(output),
		)
	}

	return output, nil
}

// PickService — механизм автозапуска для ОС goos: неизвестная ОС — отказ, а не установка
// без автозапуска.
func PickService(goos string, paths Paths, runner Runner) (Service, error) {
	switch goos {
	case GOOSDarwin:
		return launchd{
			paths:  paths,
			runner: runner,
			pause:  time.Sleep,
			uid:    strconv.Itoa(os.Getuid()),
		}, nil
	case GOOSWindows:
		account, err := currentAccount()
		if err != nil {
			return nil, err
		}

		return newSchtasks(paths, runner, account, time.Sleep), nil
	default:
		return nil, fmt.Errorf("%w: autostart for %s is not supported", ErrInstall, goos)
	}
}

// unitData — подстановки записи автозапуска.
type unitData struct {
	Label       string
	Task        string
	Binary      string
	Log         string
	UserID      string
	Fingerprint string
}

// renderLaunchd — запись launchd для бинарника binary.
func renderLaunchd(binary string, paths Paths) ([]byte, error) {
	return renderUnit("launchd.plist.tmpl", unitData{
		Label:       Label,
		Task:        TaskName,
		Binary:      binary,
		Log:         paths.ServiceLog,
		UserID:      "",
		Fingerprint: "",
	})
}

// renderTask — XML задачи планировщика Windows в UTF-16 с BOM (другой кодировки `schtasks`
// не принимает) и отпечаток этой записи, по которому сверяется уже стоящая задача.
func renderTask(binary, account string) ([]byte, string, error) {
	if account == "" {
		return nil, "", fmt.Errorf("%w: task owner is unknown", ErrInstall)
	}

	data := unitData{
		Label:       Label,
		Task:        TaskName,
		Binary:      binary,
		Log:         "",
		UserID:      account,
		Fingerprint: "",
	}

	base, err := renderUnit("schtasks.xml.tmpl", data)
	if err != nil {
		return nil, "", err
	}

	data.Fingerprint = fingerprint(base)

	unit, err := renderUnit("schtasks.xml.tmpl", data)
	if err != nil {
		return nil, "", err
	}

	return encodeUTF16(string(unit)), data.Fingerprint, nil
}

// fingerprint — отпечаток отрендеренной записи: планировщик нормализует XML, поэтому
// побайтово сверять его вывод с шаблоном нельзя, а отпечаток он несёт в `<Description>` как
// есть. Сменился шаблон, аргументы или путь к бинарнику — сменился и отпечаток.
func fingerprint(unit []byte) string {
	sum := sha256.Sum256(unit)

	return taskFingerprintMark + hex.EncodeToString(sum[:])[:fingerprintLength]
}

// renderUnit подставляет адреса в шаблон записи.
func renderUnit(name string, data unitData) ([]byte, error) {
	text, err := unitTemplates.ReadFile("templates/" + name)
	if err != nil {
		return nil, fmt.Errorf("%w: template %s: %w", ErrInstall, name, err)
	}

	unit, err := template.New(name).Funcs(template.FuncMap{"xml": escapeXML}).Parse(string(text))
	if err != nil {
		return nil, fmt.Errorf("%w: template %s: %w", ErrInstall, name, err)
	}

	var rendered bytes.Buffer

	err = unit.Execute(&rendered, data)
	if err != nil {
		return nil, fmt.Errorf("%w: template %s: %w", ErrInstall, name, err)
	}

	return rendered.Bytes(), nil
}

// escapeXML — путь внутри XML-записи: в имени каталога может стоять `&`.
func escapeXML(value string) string {
	var escaped bytes.Buffer

	_ = xml.EscapeText(&escaped, []byte(value))

	return escaped.String()
}

// encodeUTF16 — UTF-16 с BOM в прямом порядке байтов.
func encodeUTF16(text string) []byte {
	units := utf16.Encode([]rune(text))
	data := make([]byte, 0, 2*len(units)+2)
	data = append(data, 0xFF, 0xFE)

	for _, unit := range units {
		data = append(data, byte(unit), byte(unit>>8))
	}

	return data
}

// decodeUTF16 читает вывод `schtasks /XML`: он приходит в UTF-16 с BOM. Текст без BOM
// однобайтный и отдаётся как есть.
func decodeUTF16(text string) string {
	data := []byte(text)
	if len(data) < 2 || data[0] != 0xFF || data[1] != 0xFE {
		return text
	}

	data = data[2:]
	units := make([]uint16, 0, len(data)/2)

	for index := 0; index+1 < len(data); index += 2 {
		units = append(units, uint16(data[index])|uint16(data[index+1])<<8)
	}

	return string(utf16.Decode(units))
}
