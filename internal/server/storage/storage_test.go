package storage_test

import (
	"errors"
	"os"
	"testing"

	"github.com/google/uuid"

	"github.com/superserj/gophkeeper/internal/model"
	"github.com/superserj/gophkeeper/internal/server/storage"
)

// testDSNEnv указывает на базу для тестов хранилища. Без него тесты пропускаются:
// остальная система проверяется на хранилище в памяти.
const testDSNEnv = "GOPHKEEPER_TEST_DSN"

func newStorage(t *testing.T) *storage.Storage {
	t.Helper()

	dsn := os.Getenv(testDSNEnv)
	if dsn == "" {
		t.Skipf("переменная %s не задана", testDSNEnv)
	}

	store, err := storage.New(t.Context(), dsn)
	if err != nil {
		t.Fatalf("storage.New: %v", err)
	}
	t.Cleanup(store.Close)
	return store
}

func newUser(t *testing.T, store *storage.Storage, login string) string {
	t.Helper()

	id, err := store.CreateUser(t.Context(), storage.User{
		Login:        login,
		PasswordHash: "argon2id$hash",
		SaltAuth:     []byte("salt-auth"),
		SaltData:     []byte("salt-data"),
		KDFVersion:   1,
		Verifier:     []byte("verifier"),
	})
	if err != nil {
		t.Fatalf("CreateUser: %v", err)
	}
	return id
}

func TestCreateUserAndGet(t *testing.T) {
	ctx := t.Context()
	store := newStorage(t)
	login := uniqueLogin(t)

	id := newUser(t, store, login)

	user, err := store.GetUserByLogin(ctx, login)
	if err != nil {
		t.Fatalf("GetUserByLogin: %v", err)
	}
	if user.ID != id || string(user.SaltData) != "salt-data" {
		t.Fatalf("прочитан пользователь %+v", user)
	}

	duplicate := storage.User{
		Login:        login,
		PasswordHash: "argon2id$hash",
		SaltAuth:     []byte("salt-auth"),
		SaltData:     []byte("salt-data"),
		KDFVersion:   1,
		Verifier:     []byte("verifier"),
	}
	if _, err := store.CreateUser(ctx, duplicate); !errors.Is(err, storage.ErrLoginTaken) {
		t.Fatalf("повторная регистрация дала %v, ожидалась ErrLoginTaken", err)
	}
	if _, err := store.GetUserByLogin(ctx, login+"-absent"); !errors.Is(err, storage.ErrUserNotFound) {
		t.Fatalf("неизвестный логин дал %v, ожидалась ErrUserNotFound", err)
	}
}

func TestSaveSecretAssignsRevisions(t *testing.T) {
	ctx := t.Context()
	store := newStorage(t)
	userID := newUser(t, store, uniqueLogin(t))

	first, err := store.SaveSecret(ctx, userID, model.SecretRecord{ID: newUUID(t), Payload: []byte("one")}, 0)
	if err != nil {
		t.Fatalf("SaveSecret: %v", err)
	}
	second, err := store.SaveSecret(ctx, userID, model.SecretRecord{ID: newUUID(t), Payload: []byte("two")}, 0)
	if err != nil {
		t.Fatalf("SaveSecret: %v", err)
	}
	if second != first+1 {
		t.Fatalf("ревизии идут не подряд: %d и %d", first, second)
	}
}

func TestSaveSecretDetectsConflict(t *testing.T) {
	ctx := t.Context()
	store := newStorage(t)
	userID := newUser(t, store, uniqueLogin(t))
	id := newUUID(t)

	revision, err := store.SaveSecret(ctx, userID, model.SecretRecord{ID: id, Payload: []byte("one")}, 0)
	if err != nil {
		t.Fatalf("SaveSecret: %v", err)
	}
	if _, err = store.SaveSecret(ctx, userID, model.SecretRecord{ID: id, Payload: []byte("two")}, revision); err != nil {
		t.Fatalf("SaveSecret поверх актуальной ревизии: %v", err)
	}

	_, err = store.SaveSecret(ctx, userID, model.SecretRecord{ID: id, Payload: []byte("three")}, revision)
	var conflict *storage.ConflictError
	if !errors.As(err, &conflict) {
		t.Fatalf("получено %v, ожидался конфликт", err)
	}
	if string(conflict.Current.Payload) != "two" {
		t.Fatalf("в конфликте пришла версия %q", conflict.Current.Payload)
	}

	_, err = store.SaveSecret(ctx, userID, model.SecretRecord{ID: newUUID(t), Payload: []byte("new")}, 5)
	if !errors.As(err, &conflict) {
		t.Fatalf("новая запись с чужой базовой ревизией дала %v", err)
	}
}

func TestEachSecretSinceOrdersByRevision(t *testing.T) {
	ctx := t.Context()
	store := newStorage(t)
	userID := newUser(t, store, uniqueLogin(t))

	var firstRevision int64
	for i := 0; i < 3; i++ {
		revision, err := store.SaveSecret(ctx, userID, model.SecretRecord{ID: newUUID(t), Payload: []byte("data")}, 0)
		if err != nil {
			t.Fatalf("SaveSecret: %v", err)
		}
		if i == 0 {
			firstRevision = revision
		}
	}

	var revisions []int64
	err := store.EachSecretSince(ctx, userID, firstRevision, func(rec model.SecretRecord) error {
		revisions = append(revisions, rec.Revision)
		return nil
	})
	if err != nil {
		t.Fatalf("EachSecretSince: %v", err)
	}
	if len(revisions) != 2 {
		t.Fatalf("получено %d изменений, ожидалось 2", len(revisions))
	}
	if revisions[0] >= revisions[1] {
		t.Fatalf("изменения пришли не по возрастанию: %v", revisions)
	}
}

func TestEachSecretSinceReturnsEverythingAcrossPages(t *testing.T) {
	ctx := t.Context()
	store := newStorage(t)
	userID := newUser(t, store, uniqueLogin(t))

	// Записи заведомо не помещаются в одну страницу ни по объёму, ни по числу:
	// постраничное чтение не должно терять их и повторять.
	const (
		count       = 5
		payloadSize = 3 << 20
	)
	payload := make([]byte, payloadSize)
	ids := make(map[string]bool, count)
	for i := 0; i < count; i++ {
		id := newUUID(t)
		ids[id] = false
		if _, err := store.SaveSecret(ctx, userID, model.SecretRecord{ID: id, Payload: payload}, 0); err != nil {
			t.Fatalf("SaveSecret: %v", err)
		}
	}

	var previous int64
	err := store.EachSecretSince(ctx, userID, 0, func(rec model.SecretRecord) error {
		seen, known := ids[rec.ID]
		if !known {
			t.Fatalf("пришла чужая запись %s", rec.ID)
		}
		if seen {
			t.Fatalf("запись %s пришла дважды", rec.ID)
		}
		if rec.Revision <= previous {
			t.Fatalf("ревизии не растут: %d после %d", rec.Revision, previous)
		}
		ids[rec.ID] = true
		previous = rec.Revision
		return nil
	})
	if err != nil {
		t.Fatalf("EachSecretSince: %v", err)
	}

	for id, seen := range ids {
		if !seen {
			t.Fatalf("запись %s потерялась между страницами", id)
		}
	}
}

func TestEachSecretSinceStopsOnError(t *testing.T) {
	ctx := t.Context()
	store := newStorage(t)
	userID := newUser(t, store, uniqueLogin(t))

	if _, err := store.SaveSecret(ctx, userID, model.SecretRecord{ID: newUUID(t), Payload: []byte("data")}, 0); err != nil {
		t.Fatalf("SaveSecret: %v", err)
	}

	sentinel := errors.New("stop")
	err := store.EachSecretSince(ctx, userID, 0, func(model.SecretRecord) error { return sentinel })
	if !errors.Is(err, sentinel) {
		t.Fatalf("получено %v, ожидалась ошибка обработчика", err)
	}
}

func TestGetSecret(t *testing.T) {
	ctx := t.Context()
	store := newStorage(t)
	userID := newUser(t, store, uniqueLogin(t))
	id := newUUID(t)

	if _, err := store.SaveSecret(ctx, userID, model.SecretRecord{ID: id, Payload: []byte("one")}, 0); err != nil {
		t.Fatalf("SaveSecret: %v", err)
	}

	rec, err := store.GetSecret(ctx, userID, id)
	if err != nil {
		t.Fatalf("GetSecret: %v", err)
	}
	if string(rec.Payload) != "one" {
		t.Fatalf("прочитана запись %+v", rec)
	}
	if _, err := store.GetSecret(ctx, userID, newUUID(t)); !errors.Is(err, storage.ErrSecretNotFound) {
		t.Fatalf("отсутствующая запись дала %v", err)
	}
}

func TestDeleteStoresTombstone(t *testing.T) {
	ctx := t.Context()
	store := newStorage(t)
	userID := newUser(t, store, uniqueLogin(t))
	id := newUUID(t)

	revision, err := store.SaveSecret(ctx, userID, model.SecretRecord{ID: id, Payload: []byte("data")}, 0)
	if err != nil {
		t.Fatalf("SaveSecret: %v", err)
	}
	// У отметки об удалении нет полезной нагрузки — она не должна ломать запись.
	if _, err := store.SaveSecret(ctx, userID, model.SecretRecord{ID: id, Deleted: true}, revision); err != nil {
		t.Fatalf("удаление не сохранилось: %v", err)
	}

	rec, err := store.GetSecret(ctx, userID, id)
	if err != nil {
		t.Fatalf("GetSecret: %v", err)
	}
	if !rec.Deleted || len(rec.Payload) != 0 {
		t.Fatalf("после удаления прочитана запись %+v", rec)
	}
}

func TestSecretsAreIsolatedBetweenUsers(t *testing.T) {
	ctx := t.Context()
	store := newStorage(t)
	first := newUser(t, store, uniqueLogin(t))
	second := newUser(t, store, uniqueLogin(t))
	id := newUUID(t)

	if _, err := store.SaveSecret(ctx, first, model.SecretRecord{ID: id, Payload: []byte("first")}, 0); err != nil {
		t.Fatalf("SaveSecret: %v", err)
	}
	// Тот же идентификатор у второго пользователя — это его собственная запись.
	if _, err := store.SaveSecret(ctx, second, model.SecretRecord{ID: id, Payload: []byte("second")}, 0); err != nil {
		t.Fatalf("SaveSecret второму пользователю: %v", err)
	}

	rec, err := store.GetSecret(ctx, first, id)
	if err != nil {
		t.Fatalf("GetSecret: %v", err)
	}
	if string(rec.Payload) != "first" {
		t.Fatalf("данные пользователей перемешались: %q", rec.Payload)
	}
}

func TestSaveSecretRejectsUnknownUser(t *testing.T) {
	ctx := t.Context()
	store := newStorage(t)

	if _, err := store.SaveSecret(ctx, "-1", model.SecretRecord{ID: newUUID(t)}, 0); !errors.Is(err, storage.ErrUserNotFound) {
		t.Fatalf("получено %v, ожидалась ErrUserNotFound", err)
	}
	// Идентификатор не в формате ключа схемы — это чужой пользователь, а не сбой.
	if _, err := store.SaveSecret(ctx, "not-a-key", model.SecretRecord{ID: newUUID(t)}, 0); !errors.Is(err, storage.ErrUserNotFound) {
		t.Fatalf("получено %v, ожидалась ErrUserNotFound", err)
	}
}

func TestNewReportsBadDSN(t *testing.T) {
	if os.Getenv(testDSNEnv) == "" {
		t.Skipf("переменная %s не задана", testDSNEnv)
	}
	if _, err := storage.New(t.Context(), "postgres://absent:5432/none"); err == nil {
		t.Fatal("хранилище открылось с нерабочим DSN")
	}
}

// uniqueLogin даёт каждому тесту собственного пользователя: база между тестами
// не очищается, чтобы не мешать параллельным запускам.
func uniqueLogin(t *testing.T) string {
	t.Helper()
	return "user-" + uuid.NewString()
}

func newUUID(t *testing.T) string {
	t.Helper()
	return uuid.NewString()
}
