package install

import (
	"bytes"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"time"
)

// runCommand запускает команду ОС и отдаёт её вывод вместе с кодом ошибки.
func runCommand(name string, args []string) (string, error) {
	// Контекста у шага нет: команды автозапуска короткие, и отменять их установка не умеет.
	output, err := exec.Command(name, args...).CombinedOutput() //nolint:gosec,noctx // команды ОС, аргументы свои

	return string(output), err
}

// fileHasContent — файл есть, и его содержимое ровно content. На этом стоит идемпотентность:
// совпало — шаг не переделывается.
func fileHasContent(path string, content []byte) (bool, error) {
	current, err := os.ReadFile(path)

	switch {
	case err == nil:
		return bytes.Equal(current, content), nil
	case os.IsNotExist(err):
		return false, nil
	default:
		return false, fmt.Errorf("%w: %s: %w", ErrInstall, path, err)
	}
}

// writeFile пишет файл через временный и переименование: заменяемый файл не бывает
// полупустым, а работающий бинарник на месте перезаписать нельзя вовсе.
func writeFile(path string, content []byte, mode os.FileMode) error {
	directory := filepath.Dir(path)

	err := os.MkdirAll(directory, dirMode)
	if err != nil {
		return fmt.Errorf("%w: %s: %w", ErrInstall, directory, err)
	}

	temporary, err := os.CreateTemp(directory, filepath.Base(path)+".*")
	if err != nil {
		return fmt.Errorf("%w: %s: %w", ErrInstall, directory, err)
	}

	defer func() { _, _ = removeFile(temporary.Name()) }()

	err = writeAndClose(temporary, content, mode)
	if err != nil {
		return err
	}

	err = placeFile(temporary.Name(), path, os.Rename)
	if err != nil {
		return err
	}

	// Права «только владельцу» на Windows не работают: там закрывает ACL, и просьба о таких
	// правах значит именно это.
	if mode&othersMask == 0 {
		_, err = restrictToOwner(path, mode, false)

		return err
	}

	return nil
}

// placeFile ставит готовый файл на место. Простое переименование Windows отвергает, когда на
// месте идущий бинарник: файл образа заблокирован, и перезаписать его нельзя — а переименовать
// можно. Прежний файл уводится в сторону, новый встаёт на место, уведённый удаляется, когда
// его отпустит прежний процесс: на этом запуске или на следующем. Новый файл не встал —
// прежний возвращается, иначе машина осталась бы без бинарника.
func placeFile(temporary, path string, rename func(old, new string) error) error {
	err := rename(temporary, path)
	if err == nil {
		return nil
	}

	aside, asideErr := moveAside(path, rename)
	if asideErr != nil {
		return fmt.Errorf("%w: %s: %w", ErrInstall, path, err)
	}

	err = rename(temporary, path)
	if err != nil {
		_ = rename(aside, path)

		return fmt.Errorf("%w: %s: %w", ErrInstall, path, err)
	}

	_, _ = removeFile(aside)

	return nil
}

// moveAside уводит лежащий файл в сторону и отдаёт его новый адрес.
func moveAside(path string, rename func(old, new string) error) (string, error) {
	aside := path + asideSuffix

	_, err := removeFile(aside)
	if err != nil {
		// Прежний уведённый файл ещё держит процесс — имя берётся другое, а уборкой
		// занимается следующий запуск.
		aside = path + asideSuffix + "." + strconv.FormatInt(time.Now().UnixNano(), 10)
	}

	err = rename(path, aside)
	if err != nil {
		return "", fmt.Errorf("%w: %s: %w", ErrInstall, path, err)
	}

	return aside, nil
}

// sweepAside убирает файлы, уведённые в сторону прошлыми установками: процесс, который их
// держал, давно вышел. Отказ уборки — не отказ установки: файл держат, и он уйдёт позже.
func sweepAside(path string) {
	leftovers, err := filepath.Glob(path + asideSuffix + "*")
	if err != nil {
		return
	}

	for _, leftover := range leftovers {
		_, _ = removeFile(leftover)
	}
}

// writeAndClose пишет содержимое, ставит права и закрывает файл.
func writeAndClose(file *os.File, content []byte, mode os.FileMode) error {
	_, err := file.Write(content)
	if err != nil {
		_ = file.Close()

		return fmt.Errorf("%w: %s: %w", ErrInstall, file.Name(), err)
	}

	err = file.Chmod(mode)
	if err != nil {
		_ = file.Close()

		return fmt.Errorf("%w: %s: %w", ErrInstall, file.Name(), err)
	}

	err = file.Close()
	if err != nil {
		return fmt.Errorf("%w: %s: %w", ErrInstall, file.Name(), err)
	}

	return nil
}

// removeFile удаляет файл; его отсутствие — не ошибка, а «удалять нечего».
func removeFile(path string) (bool, error) {
	if path == "" {
		return false, nil
	}

	err := os.Remove(path)

	switch {
	case err == nil:
		return true, nil
	case os.IsNotExist(err):
		return false, nil
	default:
		return false, fmt.Errorf("%w: %s: %w", ErrInstall, path, err)
	}
}

// ensureDir создаёт каталог установки закрытым от других пользователей машины: в нём лежит
// файл с секретом. Лежащий каталог приводит к тому же шаг «доступ»: там это видно в отчёте.
func ensureDir(path string) (Change, error) {
	info, err := os.Stat(path)

	switch {
	case err == nil && info.IsDir():
		return Change{Done: false, Note: "already there, " + path}, nil
	case err == nil:
		return Change{Done: false, Note: ""}, fmt.Errorf("%w: %s is not a directory", ErrInstall, path)
	case os.IsNotExist(err):
	default:
		return Change{Done: false, Note: ""}, fmt.Errorf("%w: %s: %w", ErrInstall, path, err)
	}

	err = os.MkdirAll(path, dirMode)
	if err != nil {
		return Change{Done: false, Note: ""}, fmt.Errorf("%w: %s: %w", ErrInstall, path, err)
	}

	_, err = restrictToOwner(path, dirMode, true)
	if err != nil {
		return Change{Done: false, Note: ""}, err
	}

	return Change{Done: true, Note: "created, " + path}, nil
}

// ensureAccess закрывает каталог установки и файл настроек от других пользователей машины:
// в настройках секрет. Шаг свой, а не часть шагов «каталог» и «настройки»: лежащий файл
// установка по содержимому не трогает, а доступ к нему — приводит.
func ensureAccess(paths Paths) (Change, error) {
	closedDir, err := restrictToOwner(paths.Dir, dirMode, true)
	if err != nil {
		return Change{Done: false, Note: ""}, err
	}

	closedConfig, err := restrictToOwner(paths.Config, secretMode, false)
	if err != nil {
		return Change{Done: false, Note: ""}, err
	}

	if closedDir || closedConfig {
		return Change{Done: true, Note: "closed to the owner only, " + paths.Dir}, nil
	}

	return Change{Done: false, Note: "owner only, " + paths.Dir}, nil
}

// restrictToOwner закрывает путь от других пользователей машины и отвечает, пришлось ли
// править. На POSIX закрывают права 0700 и 0600. На Windows прав нет: `os.Chmod` правит там
// только флаг «только чтение», и секрет закрывает ACL — одна запись владельца и снятое
// наследование профиля, по которому путь иначе открыт администраторам машины. Каталог несёт
// запись наследуемой `(OI)(CI)`: созданные в нём файлы закрыты тем же.
func restrictToOwner(path string, mode os.FileMode, directory bool) (bool, error) {
	if runtime.GOOS != GOOSWindows {
		return restrictByMode(path, mode)
	}

	closed, err := closedToOwner(path)
	if err != nil {
		return false, err
	}

	if closed {
		return false, nil
	}

	account, err := currentAccount()
	if err != nil {
		return false, err
	}

	rights := "(F)"
	if directory {
		rights = "(OI)(CI)(F)"
	}

	// `*SID` вместо имени: имя учётной записи локализовано, а SID — тот же адрес, по
	// которому запись и сверяется.
	output, err := runCommand("icacls", []string{
		path, "/inheritance:r", "/grant:r", "*" + account + ":" + rights,
	})
	if err != nil {
		return false, fmt.Errorf("%w: icacls %s: %w: %s", ErrInstall, path, err, strings.TrimSpace(output))
	}

	return true, nil
}

// restrictByMode доводит права пути до mode: лежащий путь мог быть создан прежней
// установкой с другими правами.
func restrictByMode(path string, mode os.FileMode) (bool, error) {
	info, err := os.Stat(path)
	if err != nil {
		return false, fmt.Errorf("%w: %s: %w", ErrInstall, path, err)
	}

	if info.Mode().Perm() == mode.Perm() {
		return false, nil
	}

	err = os.Chmod(path, mode)
	if err != nil {
		return false, fmt.Errorf("%w: %s: %w", ErrInstall, path, err)
	}

	return true, nil
}

// closedToOwner — закрыт ли путь: ровно одна запись доступа, и она своя, а не унаследованная
// от профиля. Имена учётных записей `icacls` отдаёт локализованными, поэтому читаются только
// его флаги: `(I)` — запись пришла наследованием.
func closedToOwner(path string) (bool, error) {
	output, err := runCommand("icacls", []string{path})
	if err != nil {
		return false, fmt.Errorf("%w: icacls %s: %w: %s", ErrInstall, path, err, strings.TrimSpace(output))
	}

	entries := aclEntries(output)

	return len(entries) == 1 && !strings.Contains(entries[0], "(I)"), nil
}

// aclEntries — строки записей доступа в выводе `icacls`: он печатает путь и записи до первой
// пустой строки, дальше идёт его собственный итог.
func aclEntries(output string) []string {
	entries := make([]string, 0, aclEntriesGuess)

	for _, line := range strings.Split(output, "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			break
		}

		if strings.Contains(line, ":(") {
			entries = append(entries, line)
		}
	}

	return entries
}
