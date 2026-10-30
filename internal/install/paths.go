// Package install ставит сторожа одной командой и снимает его: бинарник в каталог запуска,
// файл настроек с секретом, запись автозапуска ОС, проверка живого сервиса. Каждый шаг
// идемпотентен: уже сделанное не переделывается, а подтверждается строкой отчёта.
package install

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"

	"github.com/kerbyfc/ipguard/internal/config"
)

const (
	// BinaryName — имя бинарника в каталоге запуска.
	BinaryName = "ipguard"
	// Label — метка службы launchd.
	Label = "com.kerbyfc.ipguard"
	// TaskName — имя задачи планировщика Windows.
	TaskName = "claude-ipguard"
	// ServiceLogName — файл вывода процесса службы: туда идёт то, что минует журнал, —
	// паники и отказы до его открытия. Его пишет launchd, а не сторож, и мал он именно
	// поэтому: строки журнала в него не дублируются.
	ServiceLogName = "launchd.log"

	// GOOSDarwin и GOOSWindows — ОС, для которых есть автозапуск.
	GOOSDarwin  = "darwin"
	GOOSWindows = "windows"

	dirMode    os.FileMode = 0o700
	secretMode os.FileMode = 0o600
	binaryMode os.FileMode = 0o755
	unitMode   os.FileMode = 0o644

	// othersMask — биты группы и остальных: просьба о правах без них значит «только
	// владельцу», и на Windows её исполняет ACL, а не права.
	othersMask os.FileMode = 0o077
	// aclEntriesGuess — сколько записей доступа ждать от `icacls`: у пути в профиле их три
	// (владелец, администраторы, система), запас — на четвёртую.
	aclEntriesGuess = 4
	// asideSuffix — хвост имени файла, уведённого в сторону: так уходит заблокированный
	// бинарник идущей службы, на место которого встаёт новый.
	asideSuffix = ".old"
)

// ErrInstall — установка не удалась.
var ErrInstall = errors.New("ipguard install failed")

// Paths — адреса установки. Они те же, что читает `serve`: каталог установки из
// `internal/config`, бинарник в `~/.local/bin`.
type Paths struct {
	// Binary — бинарник, который запускает автозапуск.
	Binary string
	// Dir — каталог установки с настройками и журналом.
	Dir string
	// Config — файл настроек.
	Config string
	// ServiceLog — вывод самого процесса службы: паники и отказы до открытия журнала. Строки
	// журнала сюда не идут, журнал пишется в свой ротируемый файл из настроек.
	ServiceLog string
	// Unit — файл записи автозапуска; у планировщика Windows запись живёт в нём самом,
	// поэтому здесь пусто.
	Unit string
}

// DefaultPaths — адреса установки этой машины.
func DefaultPaths(goos string) (Paths, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return Paths{}, fmt.Errorf("%w: home directory is unknown: %w", ErrInstall, err)
	}

	return NewPaths(goos, home)
}

// NewPaths — адреса установки для ОС goos в домашнем каталоге home. ОС без автозапуска —
// отказ, а не установка без автозапуска.
func NewPaths(goos, home string) (Paths, error) {
	if home == "" {
		return Paths{}, fmt.Errorf("%w: home directory is empty", ErrInstall)
	}

	dir := filepath.Join(home, filepath.FromSlash(config.DirName))

	paths := Paths{
		Binary:     filepath.Join(home, ".local", "bin", BinaryName),
		Dir:        dir,
		Config:     filepath.Join(dir, config.FileName),
		ServiceLog: filepath.Join(dir, ServiceLogName),
		Unit:       "",
	}

	switch goos {
	case GOOSDarwin:
		paths.Unit = filepath.Join(home, "Library", "LaunchAgents", Label+".plist")
	case GOOSWindows:
		paths.Binary += ".exe"
	default:
		return Paths{}, fmt.Errorf("%w: autostart for %s is not supported", ErrInstall, goos)
	}

	return paths, nil
}
