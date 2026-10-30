//go:build windows

package cli

import "golang.org/x/sys/windows"

var (
	kernel32             = windows.NewLazySystemDLL("kernel32.dll")
	user32               = windows.NewLazySystemDLL("user32.dll")
	procFreeConsole      = kernel32.NewProc("FreeConsole")
	procGetConsoleWindow = kernel32.NewProc("GetConsoleWindow")
	procShowWindow       = user32.NewProc("ShowWindow")
)

// hideServiceWindow убирает консольное окно службы: задача планировщика запускает serve с
// InteractiveToken, и без этого окно консоли появляется на рабочем столе при каждом входе.
// Закрытие окна владельцем убивает прокси, поэтому служба его не показывает. Сначала
// FreeConsole отцепляет процесс от консоли — окно закрывается целиком; если отцепление
// не удалось, окно скрывается ShowWindow.
func hideServiceWindow() {
	detached, _, _ := procFreeConsole.Call()
	if detached != 0 {
		return
	}

	console, _, _ := procGetConsoleWindow.Call()
	if console == 0 {
		return
	}

	const swHide = 0 // WinAPI: SW_HIDE.

	_, _, _ = procShowWindow.Call(console, swHide)
}
