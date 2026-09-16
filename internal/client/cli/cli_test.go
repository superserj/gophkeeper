package cli_test

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/superserj/gophkeeper/internal/client/cli"
	"github.com/superserj/gophkeeper/internal/client/localstore"
	"github.com/superserj/gophkeeper/internal/crypto"
)

const (
	testLogin  = "user"
	testMaster = "master password"
)

// prepareStore создаёт локальное хранилище с профилем: команды, которым не нужен
// сервер, работают полностью офлайн.
func prepareStore(t *testing.T) string {
	t.Helper()

	path := filepath.Join(t.TempDir(), "vault.db")
	store, err := localstore.Open(path)
	if err != nil {
		t.Fatalf("localstore.Open: %v", err)
	}
	defer func() {
		_ = store.Close()
	}()

	saltAuth, err := crypto.NewSalt()
	if err != nil {
		t.Fatalf("NewSalt: %v", err)
	}
	saltData, err := crypto.NewSalt()
	if err != nil {
		t.Fatalf("NewSalt: %v", err)
	}
	verifier, err := crypto.NewVerifier(crypto.DeriveDataKey(testMaster, saltData), testLogin)
	if err != nil {
		t.Fatalf("NewVerifier: %v", err)
	}

	err = store.SaveProfile(localstore.Profile{
		Login:      testLogin,
		SaltAuth:   saltAuth,
		SaltData:   saltData,
		KDFVersion: crypto.KDFVersion,
		Verifier:   verifier,
	})
	if err != nil {
		t.Fatalf("SaveProfile: %v", err)
	}
	return path
}

// run выполняет команду и возвращает её вывод.
func run(t *testing.T, args ...string) (string, error) {
	t.Helper()
	return runWithInput(t, "", args...)
}

// runWithInput выполняет команду, подав ей во ввод секретные значения:
// пароль и реквизиты карты нельзя передавать флагами.
func runWithInput(t *testing.T, input string, args ...string) (string, error) {
	t.Helper()

	var out bytes.Buffer
	err := cli.Run(t.Context(), args, strings.NewReader(input), &out, "v1.0.0", "2026-09-17")
	return out.String(), err
}

func TestVersionCommand(t *testing.T) {

	output, err := run(t, "version")
	if err != nil {
		t.Fatalf("version: %v", err)
	}
	if !strings.Contains(output, "v1.0.0") || !strings.Contains(output, "2026-09-17") {
		t.Fatalf("вывод команды version: %q", output)
	}
}

func TestAddAndListSecrets(t *testing.T) {
	t.Setenv("GOPHKEEPER_MASTER_PASSWORD", testMaster)
	store := prepareStore(t)

	output, err := runWithInput(t, "p\n", "--store", store, "add", "credentials", "--name", "bank", "--login", "u")
	if err != nil {
		t.Fatalf("add credentials: %v", err)
	}
	id := strings.TrimSpace(output)
	if id == "" {
		t.Fatal("команда add не напечатала идентификатор")
	}

	output, err = run(t, "--store", store, "list")
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	if !strings.Contains(output, "bank") || !strings.Contains(output, "not synchronized") {
		t.Fatalf("вывод команды list: %q", output)
	}

	output, err = run(t, "--store", store, "get", id)
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	if !strings.Contains(output, "login: u") || !strings.Contains(output, "password: p") {
		t.Fatalf("вывод команды get: %q", output)
	}

	if _, err = run(t, "--store", store, "delete", id); err != nil {
		t.Fatalf("delete: %v", err)
	}

	output, err = run(t, "--store", store, "list")
	if err != nil {
		t.Fatalf("list после удаления: %v", err)
	}
	if !strings.Contains(output, "store is empty") {
		t.Fatalf("после удаления список: %q", output)
	}
}

func TestAddTextFromFileAndBinary(t *testing.T) {
	t.Setenv("GOPHKEEPER_MASTER_PASSWORD", testMaster)
	store := prepareStore(t)

	dir := t.TempDir()
	textPath := filepath.Join(dir, "note.txt")
	if err := os.WriteFile(textPath, []byte("секретная заметка"), 0o600); err != nil {
		t.Fatalf("write text: %v", err)
	}
	binaryPath := filepath.Join(dir, "blob.bin")
	if err := os.WriteFile(binaryPath, []byte{0, 1, 2, 3}, 0o600); err != nil {
		t.Fatalf("write binary: %v", err)
	}

	if _, err := run(t, "--store", store, "add", "text", "--name", "note", "--file", textPath); err != nil {
		t.Fatalf("add text: %v", err)
	}

	// Без файла текст читается из ввода, а не из флага.
	textID, err := runWithInput(t, "секрет из ввода\n", "--store", store, "add", "text", "--name", "typed")
	if err != nil {
		t.Fatalf("add text из ввода: %v", err)
	}
	shown, err := run(t, "--store", store, "get", strings.TrimSpace(textID))
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	if !strings.Contains(shown, "text: секрет из ввода") {
		t.Fatalf("вывод текста: %q", shown)
	}

	output, err := run(t, "--store", store, "add", "binary", "--name", "blob", "--file", binaryPath)
	if err != nil {
		t.Fatalf("add binary: %v", err)
	}
	binaryID := strings.TrimSpace(output)
	source, err := os.ReadFile(binaryPath)
	if err != nil {
		t.Fatalf("read source: %v", err)
	}

	outPath := filepath.Join(dir, "restored.bin")
	if _, err := run(t, "--store", store, "get", binaryID, "--out", outPath); err != nil {
		t.Fatalf("get --out: %v", err)
	}

	restored, err := os.ReadFile(outPath)
	if err != nil {
		t.Fatalf("read restored: %v", err)
	}
	if !bytes.Equal(restored, source) {
		t.Fatalf("восстановлено %v, ожидалось %v", restored, source)
	}
}

func TestAddCard(t *testing.T) {
	t.Setenv("GOPHKEEPER_MASTER_PASSWORD", testMaster)
	store := prepareStore(t)

	output, err := runWithInput(t, "4111111111111111\n123\n", "--store", store, "add", "card",
		"--name", "visa", "--holder", "IVAN IVANOV", "--expires", "12/29")
	if err != nil {
		t.Fatalf("add card: %v", err)
	}

	output, err = run(t, "--store", store, "get", strings.TrimSpace(output))
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	// Оба секретных значения читаются из одного потока: код проверки не должен
	// потеряться после номера карты.
	if !strings.Contains(output, "4111111111111111") || !strings.Contains(output, "cvv: 123") {
		t.Fatalf("вывод карты: %q", output)
	}
}

func TestCommandsRequireProfile(t *testing.T) {
	t.Setenv("GOPHKEEPER_MASTER_PASSWORD", testMaster)
	store := filepath.Join(t.TempDir(), "vault.db")

	if _, err := run(t, "--store", store, "list"); err == nil {
		t.Fatal("команда list сработала без профиля")
	}
}

func TestWrongMasterPassword(t *testing.T) {
	store := prepareStore(t)
	t.Setenv("GOPHKEEPER_MASTER_PASSWORD", "wrong password")

	if _, err := run(t, "--store", store, "list"); err == nil {
		t.Fatal("хранилище открылось с неверным мастер-паролем")
	}
}

func TestResolveRequiresID(t *testing.T) {
	t.Setenv("GOPHKEEPER_MASTER_PASSWORD", testMaster)
	store := prepareStore(t)

	if _, err := run(t, "--store", store, "sync", "--resolve", "local"); err == nil {
		t.Fatal("разрешение конфликта прошло без идентификатора записи")
	}

	if _, err := run(t, "--store", store, "sync", "--resolve", "unknown", "--id", "x"); err == nil {
		t.Fatal("принят неизвестный способ разрешения конфликта")
	}
}

func TestSecretValueIsRequired(t *testing.T) {
	t.Setenv("GOPHKEEPER_MASTER_PASSWORD", testMaster)
	store := prepareStore(t)

	if _, err := runWithInput(t, "", "--store", store, "add", "credentials", "--name", "empty", "--login", "u"); err == nil {
		t.Fatal("запись сохранена с пустым паролем")
	}
}

func TestGetWritesBinaryWithOwnerOnlyPermissions(t *testing.T) {
	t.Setenv("GOPHKEEPER_MASTER_PASSWORD", testMaster)
	store := prepareStore(t)

	dir := t.TempDir()
	source := filepath.Join(dir, "blob.bin")
	if err := os.WriteFile(source, []byte{9, 8, 7}, 0o600); err != nil {
		t.Fatalf("write binary: %v", err)
	}

	output, err := run(t, "--store", store, "add", "binary", "--name", "blob", "--file", source)
	if err != nil {
		t.Fatalf("add binary: %v", err)
	}

	// Файл уже существует и открыт всем на чтение: экспорт не должен оставить его таким.
	target := filepath.Join(dir, "restored.bin")
	if err := os.WriteFile(target, []byte("old"), 0o644); err != nil {
		t.Fatalf("write target: %v", err)
	}
	if _, err := run(t, "--store", store, "get", strings.TrimSpace(output), "--out", target); err != nil {
		t.Fatalf("get --out: %v", err)
	}

	info, err := os.Stat(target)
	if err != nil {
		t.Fatalf("stat: %v", err)
	}
	if info.Mode().Perm() != 0o600 {
		t.Fatalf("права файла %v, ожидались 0600", info.Mode().Perm())
	}
}

func TestAddRejectsMissingFile(t *testing.T) {
	t.Setenv("GOPHKEEPER_MASTER_PASSWORD", testMaster)
	store := prepareStore(t)

	if _, err := run(t, "--store", store, "add", "binary", "--name", "blob", "--file", "/absent/file"); err == nil {
		t.Fatal("команда приняла несуществующий файл")
	}
}

func TestMasterPasswordIsRequired(t *testing.T) {
	t.Setenv("GOPHKEEPER_MASTER_PASSWORD", "")
	store := prepareStore(t)

	_, err := run(t, "--store", store, "list")
	if err == nil {
		t.Fatal("команда сработала без мастер-пароля")
	}
	if !strings.Contains(err.Error(), "GOPHKEEPER_MASTER_PASSWORD") {
		t.Fatalf("ошибка не подсказывает, как передать пароль: %v", err)
	}
}
