package install

import "time"

// NewLaunchdForTest — launchd с подменённым запуском команд и паузой: тесты не трогают
// настоящий launchd и не спят. Боевой код собирает ту же структуру напрямую.
func NewLaunchdForTest(paths Paths, runner Runner, uid string, pause func(time.Duration)) Service {
	return launchd{paths: paths, runner: runner, pause: pause, uid: uid}
}

// NewSchtasksForTest — планировщик Windows с подменённым запуском команд, заданным владельцем
// задачи и паузой без сна: тесты не спрашивают SID настоящей машины и не спят. Боевой код
// собирает ту же структуру напрямую.
func NewSchtasksForTest(paths Paths, runner Runner, account string) Service {
	return newSchtasks(paths, runner, account, func(time.Duration) {})
}
