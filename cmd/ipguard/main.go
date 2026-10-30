// ipguard — сторож доступа Claude: локальный HTTP-прокси, устанавливающий соединение только
// при вердикте «внешний IP машины равен ожидаемому»; установленный туннель живёт до закрытия
// пиром.
//
//	ipguard install    поставить сторожа: бинарник, настройки, автозапуск ОС и проба сервиса
//	ipguard uninstall  снять автозапуск; настройки, журнал и бинарник остаются
//	ipguard enable     прописать прокси сторожа в блок env настроек Claude Code
//	ipguard disable    убрать переменные прокси сторожа из настроек Claude Code
//	ipguard serve      поднять прокси на loopback-порту из настроек
//	ipguard check      разовая проверка внешнего IP для диагностики
//	ipguard status     вердикт поднятого сервиса: код 0 — пропуск, 3 — отказ
//	ipguard version    версия
//
// Настройки — `--config` или IPGUARD_CONFIG, иначе файл в каталоге установки
// (`~/.local/share/claude-ipguard/ipguard.yaml`); файла нет — встроенные значения, кроме
// ожидаемого IP (его задаёт установка или флаг `--expected-ip`), файл битый — выход с
// ненулевым кодом. README — tools/ipguard/README.md.
package main

import (
	"os"

	"github.com/kerbyfc/ipguard/internal/cli"
)

func main() {
	os.Exit(cli.Run(os.Args[1:]))
}
