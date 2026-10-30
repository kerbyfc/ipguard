package install

import (
	"errors"
	"os"
	"path/filepath"
	"testing"
)

// errLocked — отказ переименования поверх занятого файла: так Windows отвечает, когда на
// месте лежит бинарник идущей службы.
var errLocked = errors.New("Access is denied")

// TestPlaceFileMovesLockedFileAside: поверх занятого файла переименование не идёт, поэтому
// прежний уводится в сторону, а новый встаёт на место. Без этого установка не меняла бы
// бинарник идущей службы вовсе.
func TestPlaceFileMovesLockedFileAside(t *testing.T) {
	t.Parallel()

	directory := t.TempDir()
	path := filepath.Join(directory, "ipguard.exe")
	temporary := filepath.Join(directory, "ipguard.exe.new")

	writeInternalTestFile(t, path, "старый")
	writeInternalTestFile(t, temporary, "новый")

	locked := true
	rename := func(old, new string) error {
		if locked && new == path {
			locked = false

			return errLocked
		}

		return os.Rename(old, new)
	}

	err := placeFile(temporary, path, rename)
	if err != nil {
		t.Fatalf("place over a locked file: %v", err)
	}

	if readInternalTestFile(t, path) != "новый" {
		t.Fatalf("file at %s is %q, want the new one", path, readInternalTestFile(t, path))
	}
}

// TestEnsureBinarySweepsAside: уведённые прошлыми установками копии убирает каждый запуск —
// держащий их процесс к этому времени вышел, и бинарники в каталоге запуска не копятся.
func TestEnsureBinarySweepsAside(t *testing.T) {
	t.Parallel()

	directory := t.TempDir()
	path := filepath.Join(directory, "ipguard.exe")
	self := filepath.Join(directory, "build", "ipguard.exe")

	writeInternalTestFile(t, path, "тот же")
	writeInternalTestFile(t, path+asideSuffix, "позапрошлый")
	writeInternalTestFile(t, path+asideSuffix+".17", "давний")

	err := os.MkdirAll(filepath.Dir(self), dirMode)
	if err != nil {
		t.Fatalf("mkdir: %v", err)
	}

	writeInternalTestFile(t, self, "тот же")

	change, err := ensureBinary(self, path)
	if err != nil {
		t.Fatalf("ensure binary: %v", err)
	}

	if change.Done {
		t.Fatalf("the same binary was replaced: %+v", change)
	}

	leftovers, err := filepath.Glob(path + asideSuffix + "*")
	if err != nil {
		t.Fatalf("glob: %v", err)
	}

	if len(leftovers) != 0 {
		t.Fatalf("aside files left in the run directory: %v", leftovers)
	}
}

// TestPlaceFileReturnsLockedFileOnFailure: новый файл не встал — прежний возвращается на
// место, иначе машина осталась бы без бинарника.
func TestPlaceFileReturnsLockedFileOnFailure(t *testing.T) {
	t.Parallel()

	directory := t.TempDir()
	path := filepath.Join(directory, "ipguard.exe")
	temporary := filepath.Join(directory, "ipguard.exe.new")

	writeInternalTestFile(t, path, "старый")
	writeInternalTestFile(t, temporary, "новый")

	rename := func(old, new string) error {
		if old == temporary {
			return errLocked
		}

		return os.Rename(old, new)
	}

	err := placeFile(temporary, path, rename)
	if !errors.Is(err, ErrInstall) {
		t.Fatalf("place gave %v, want an install error", err)
	}

	if readInternalTestFile(t, path) != "старый" {
		t.Fatal("the previous binary was not returned to its place")
	}
}

// writeInternalTestFile кладёт файл или валит тест.
func writeInternalTestFile(t *testing.T, path, content string) {
	t.Helper()

	err := os.WriteFile(path, []byte(content), secretMode)
	if err != nil {
		t.Fatalf("write %s: %v", path, err)
	}
}

// readInternalTestFile читает файл или валит тест.
func readInternalTestFile(t *testing.T, path string) string {
	t.Helper()

	content, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}

	return string(content)
}
