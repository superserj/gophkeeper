package localstore

import (
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/superserj/gophkeeper/internal/model"
)

func openStore(t *testing.T) *Store {
	t.Helper()

	store, err := Open(filepath.Join(t.TempDir(), "nested", "vault.db"))
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	t.Cleanup(func() {
		_ = store.Close()
	})
	return store
}

func TestProfileRoundTrip(t *testing.T) {
	store := openStore(t)

	if _, err := store.Profile(); !errors.Is(err, ErrNoProfile) {
		t.Fatalf("пустое хранилище дало %v, ожидалась ErrNoProfile", err)
	}

	profile := Profile{
		Login:      "user",
		SaltAuth:   []byte{1, 2, 3},
		SaltData:   []byte{4, 5, 6},
		KDFVersion: 1,
		Verifier:   []byte{7, 8, 9},
	}
	if err := store.SaveProfile(profile); err != nil {
		t.Fatalf("SaveProfile: %v", err)
	}

	got, err := store.Profile()
	if err != nil {
		t.Fatalf("Profile: %v", err)
	}
	if got.Login != profile.Login || string(got.SaltData) != string(profile.SaltData) {
		t.Fatalf("прочитан профиль %+v", got)
	}
}

func TestTokenRoundTrip(t *testing.T) {
	store := openStore(t)

	token, err := store.Token()
	if err != nil {
		t.Fatalf("Token: %v", err)
	}
	if token != "" {
		t.Fatalf("в пустом хранилище нашёлся токен %q", token)
	}

	if err := store.SaveToken("jwt"); err != nil {
		t.Fatalf("SaveToken: %v", err)
	}
	if token, err = store.Token(); err != nil || token != "jwt" {
		t.Fatalf("прочитан токен %q, ошибка %v", token, err)
	}
}

func TestApplyChangeMovesCursor(t *testing.T) {
	store := openStore(t)

	revision, err := store.LastRevision()
	if err != nil {
		t.Fatalf("LastRevision: %v", err)
	}
	if revision != 0 {
		t.Fatalf("курсор пустого хранилища %d", revision)
	}

	rec := model.SecretRecord{ID: "a", Payload: []byte("cipher"), Revision: 7, UpdatedAt: time.Now()}
	if err := store.ApplyChange(rec); err != nil {
		t.Fatalf("ApplyChange: %v", err)
	}

	if revision, err = store.LastRevision(); err != nil || revision != 7 {
		t.Fatalf("курсор %d, ошибка %v", revision, err)
	}

	got, found, err := store.ServerRecord("a")
	if err != nil || !found {
		t.Fatalf("запись не найдена: %v", err)
	}
	if string(got.Payload) != "cipher" || got.Revision != 7 {
		t.Fatalf("прочитана запись %+v", got)
	}
}

func TestPutServerRecordKeepsCursor(t *testing.T) {
	store := openStore(t)

	if err := store.ApplyChange(model.SecretRecord{ID: "a", Revision: 3}); err != nil {
		t.Fatalf("ApplyChange: %v", err)
	}
	if err := store.PutServerRecord(model.SecretRecord{ID: "b", Revision: 9}); err != nil {
		t.Fatalf("PutServerRecord: %v", err)
	}

	revision, err := store.LastRevision()
	if err != nil {
		t.Fatalf("LastRevision: %v", err)
	}
	if revision != 3 {
		t.Fatalf("курсор сдвинулся до %d: между ним и 9 могли остаться чужие изменения", revision)
	}
}

func TestServerRecordMissing(t *testing.T) {
	store := openStore(t)

	_, found, err := store.ServerRecord("absent")
	if err != nil {
		t.Fatalf("ServerRecord: %v", err)
	}
	if found {
		t.Fatal("найдена несуществующая запись")
	}
}

func TestServerRecords(t *testing.T) {
	store := openStore(t)

	for _, rec := range []model.SecretRecord{
		{ID: "a", Revision: 1, Payload: []byte("one")},
		{ID: "b", Revision: 2, Deleted: true},
	} {
		if err := store.ApplyChange(rec); err != nil {
			t.Fatalf("ApplyChange: %v", err)
		}
	}

	records, err := store.ServerRecords()
	if err != nil {
		t.Fatalf("ServerRecords: %v", err)
	}
	if len(records) != 2 {
		t.Fatalf("получено %d записей, ожидалось 2", len(records))
	}
}

func TestPendingLifecycle(t *testing.T) {
	store := openStore(t)

	change := PendingChange{ID: "a", Op: OpPut, Payload: []byte("cipher"), BaseRevision: 4}
	if err := store.PutPending(change); err != nil {
		t.Fatalf("PutPending: %v", err)
	}

	got, found, err := store.Pending("a")
	if err != nil || !found {
		t.Fatalf("изменение не найдено: %v", err)
	}
	if got.BaseRevision != 4 || got.Op != OpPut {
		t.Fatalf("прочитано изменение %+v", got)
	}

	changes, err := store.PendingChanges()
	if err != nil || len(changes) != 1 {
		t.Fatalf("получено %d изменений, ошибка %v", len(changes), err)
	}

	if err := store.DropPending("a"); err != nil {
		t.Fatalf("DropPending: %v", err)
	}
	if _, found, err = store.Pending("a"); err != nil || found {
		t.Fatalf("изменение осталось после удаления: %v", err)
	}
}

func TestApplyChangeDoesNotTouchPending(t *testing.T) {
	store := openStore(t)

	if err := store.PutPending(PendingChange{ID: "a", Op: OpPut, Payload: []byte("local"), BaseRevision: 1}); err != nil {
		t.Fatalf("PutPending: %v", err)
	}
	if err := store.ApplyChange(model.SecretRecord{ID: "a", Payload: []byte("remote"), Revision: 5}); err != nil {
		t.Fatalf("ApplyChange: %v", err)
	}

	change, found, err := store.Pending("a")
	if err != nil || !found {
		t.Fatalf("локальное изменение потеряно: %v", err)
	}
	if string(change.Payload) != "local" {
		t.Fatalf("локальное изменение перезаписано версией сервера: %q", change.Payload)
	}
}

func TestOpenReportsBrokenPath(t *testing.T) {
	// Файл на месте каталога: создать каталог хранилища не получится.
	blocker := filepath.Join(t.TempDir(), "blocker")
	if err := os.WriteFile(blocker, []byte("file"), 0o600); err != nil {
		t.Fatalf("write blocker: %v", err)
	}

	if _, err := Open(filepath.Join(blocker, "vault.db")); err == nil {
		t.Fatal("хранилище открыто по некорректному пути")
	}
}
