package service_test

import (
	"errors"
	"strings"
	"testing"

	"github.com/superserj/gophkeeper/internal/crypto"
	"github.com/superserj/gophkeeper/internal/model"
	"github.com/superserj/gophkeeper/internal/server/auth"
	"github.com/superserj/gophkeeper/internal/server/service"
	"github.com/superserj/gophkeeper/internal/server/storage"
	"github.com/superserj/gophkeeper/internal/server/storage/memory"
)

const (
	testLogin  = "user"
	testMaster = "master password"
	// firstUserID — идентификатор, который хранилище в памяти выдаёт первому
	// зарегистрированному пользователю.
	firstUserID = "1"
)

func newService() *service.Service {
	return service.New(memory.New(), auth.NewTokenManager("secret", auth.TokenTTL))
}

func credentials(t *testing.T, login string) service.Credentials {
	t.Helper()

	saltAuth, err := crypto.NewSalt()
	if err != nil {
		t.Fatalf("NewSalt: %v", err)
	}
	saltData, err := crypto.NewSalt()
	if err != nil {
		t.Fatalf("NewSalt: %v", err)
	}
	verifier, err := crypto.NewVerifier(crypto.DeriveDataKey(testMaster, saltData), login)
	if err != nil {
		t.Fatalf("NewVerifier: %v", err)
	}
	return service.Credentials{
		Login:      login,
		AuthKey:    crypto.DeriveAuthKey(testMaster, saltAuth),
		SaltAuth:   saltAuth,
		SaltData:   saltData,
		KDFVersion: crypto.KDFVersion,
		Verifier:   verifier,
	}
}

func TestRegisterAndLogin(t *testing.T) {
	ctx := t.Context()
	svc := newService()
	creds := credentials(t, testLogin)

	session, err := svc.Register(ctx, creds)
	if err != nil {
		t.Fatalf("Register: %v", err)
	}
	if session.Token == "" {
		t.Fatal("регистрация не выдала токен")
	}

	logged, err := svc.Login(ctx, testLogin, creds.AuthKey)
	if err != nil {
		t.Fatalf("Login: %v", err)
	}
	if string(logged.SaltData) != string(creds.SaltData) {
		t.Fatal("вход вернул другую соль данных")
	}
	if string(logged.Verifier) != string(creds.Verifier) {
		t.Fatal("вход вернул другой верификатор")
	}
}

func TestRegisterRejectsDuplicateLogin(t *testing.T) {
	ctx := t.Context()
	svc := newService()

	if _, err := svc.Register(ctx, credentials(t, testLogin)); err != nil {
		t.Fatalf("Register: %v", err)
	}
	if _, err := svc.Register(ctx, credentials(t, testLogin)); !errors.Is(err, service.ErrLoginTaken) {
		t.Fatalf("повторная регистрация дала %v, ожидалась ErrLoginTaken", err)
	}
}

func TestRegisterValidatesInput(t *testing.T) {
	ctx := t.Context()
	svc := newService()
	valid := credentials(t, testLogin)

	tests := []struct {
		name  string
		creds service.Credentials
		want  error
	}{
		{
			name:  "no login",
			creds: service.Credentials{},
			want:  service.ErrEmptyLogin,
		},
		{
			name: "long login",
			creds: service.Credentials{
				Login: strings.Repeat("a", service.MaxLoginLength+1), AuthKey: valid.AuthKey,
				SaltAuth: valid.SaltAuth, SaltData: valid.SaltData, Verifier: valid.Verifier,
			},
			want: service.ErrBadCredentials,
		},
		{
			name: "oversized verifier",
			creds: service.Credentials{
				Login: testLogin, AuthKey: valid.AuthKey,
				SaltAuth: valid.SaltAuth, SaltData: valid.SaltData,
				Verifier: make([]byte, service.MaxVerifierSize+1),
			},
			want: service.ErrBadCredentials,
		},
		{
			name:  "no auth key",
			creds: service.Credentials{Login: testLogin, SaltAuth: valid.SaltAuth, SaltData: valid.SaltData, Verifier: valid.Verifier},
			want:  service.ErrBadCredentials,
		},
		{
			name: "short salt",
			creds: service.Credentials{
				Login: testLogin, AuthKey: valid.AuthKey,
				SaltAuth: []byte{1}, SaltData: valid.SaltData, Verifier: valid.Verifier,
			},
			want: service.ErrBadCredentials,
		},
		{
			name: "no verifier",
			creds: service.Credentials{
				Login: testLogin, AuthKey: valid.AuthKey,
				SaltAuth: valid.SaltAuth, SaltData: valid.SaltData,
			},
			want: service.ErrBadCredentials,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if _, err := svc.Register(ctx, tt.creds); !errors.Is(err, tt.want) {
				t.Fatalf("получено %v, ожидалась %v", err, tt.want)
			}
		})
	}
}

func TestLoginRejectsWrongKey(t *testing.T) {
	ctx := t.Context()
	svc := newService()

	if _, err := svc.Register(ctx, credentials(t, testLogin)); err != nil {
		t.Fatalf("Register: %v", err)
	}
	// Ключ нужной длины, но выведенный из другого пароля: иначе запрос отсеется
	// проверкой размера и тест пройдёт даже без сверки с хешем.
	wrongKey := crypto.DeriveAuthKey("another password", make([]byte, crypto.SaltSize))
	if len(wrongKey) != crypto.KeySize {
		t.Fatalf("длина ключа %d, ожидалась %d", len(wrongKey), crypto.KeySize)
	}
	if _, err := svc.Login(ctx, testLogin, wrongKey); !errors.Is(err, service.ErrBadCredentials) {
		t.Fatalf("неверный ключ дал %v, ожидалась ErrBadCredentials", err)
	}
	if _, err := svc.Login(ctx, "absent", crypto.DeriveAuthKey("x", make([]byte, crypto.SaltSize))); !errors.Is(err, service.ErrBadCredentials) {
		t.Fatalf("неизвестный логин дал %v, ожидалась ErrBadCredentials", err)
	}
	if _, err := svc.Login(ctx, "", crypto.DeriveAuthKey("x", make([]byte, crypto.SaltSize))); !errors.Is(err, service.ErrBadCredentials) {
		t.Fatalf("пустой логин дал %v, ожидалась ErrBadCredentials", err)
	}
}

func TestSaltsHidesUnknownLogin(t *testing.T) {
	ctx := t.Context()
	svc := newService()
	creds := credentials(t, testLogin)

	if _, err := svc.Register(ctx, creds); err != nil {
		t.Fatalf("Register: %v", err)
	}

	salts, err := svc.Salts(ctx, testLogin)
	if err != nil {
		t.Fatalf("Salts: %v", err)
	}
	if string(salts.SaltAuth) != string(creds.SaltAuth) {
		t.Fatal("выдана чужая соль")
	}
	if _, err := svc.Salts(ctx, "absent"); !errors.Is(err, service.ErrBadCredentials) {
		t.Fatalf("неизвестный логин дал %v, ожидалась ErrBadCredentials", err)
	}
}

func TestPushAssignsGrowingRevisions(t *testing.T) {
	ctx := t.Context()
	svc := newService()
	userID := register(t, svc)

	first, err := svc.Push(ctx, userID, model.SecretRecord{ID: "a", Payload: []byte("one")}, 0)
	if err != nil {
		t.Fatalf("Push: %v", err)
	}
	second, err := svc.Push(ctx, userID, model.SecretRecord{ID: "b", Payload: []byte("two")}, 0)
	if err != nil {
		t.Fatalf("Push: %v", err)
	}
	if second <= first {
		t.Fatalf("ревизии не растут: %d и %d", first, second)
	}
}

func TestPushDetectsConflict(t *testing.T) {
	ctx := t.Context()
	svc := newService()
	userID := register(t, svc)

	revision, err := svc.Push(ctx, userID, model.SecretRecord{ID: "a", Payload: []byte("one")}, 0)
	if err != nil {
		t.Fatalf("Push: %v", err)
	}
	if _, err := svc.Push(ctx, userID, model.SecretRecord{ID: "a", Payload: []byte("two")}, revision); err != nil {
		t.Fatalf("Push поверх актуальной ревизии: %v", err)
	}

	_, err = svc.Push(ctx, userID, model.SecretRecord{ID: "a", Payload: []byte("three")}, revision)
	var conflict *storage.ConflictError
	if !errors.As(err, &conflict) {
		t.Fatalf("получено %v, ожидался конфликт", err)
	}
	if string(conflict.Current.Payload) != "two" {
		t.Fatalf("в конфликте пришла версия %q", conflict.Current.Payload)
	}
}

func TestPushRejectsHugePayloadAndEmptyID(t *testing.T) {
	ctx := t.Context()
	svc := newService()
	userID := register(t, svc)

	huge := make([]byte, model.MaxSecretSize+1)
	if _, err := svc.Push(ctx, userID, model.SecretRecord{ID: "a", Payload: huge}, 0); !errors.Is(err, service.ErrPayloadTooLarge) {
		t.Fatalf("получено %v, ожидалась ErrPayloadTooLarge", err)
	}
	// Пустой идентификатор — некорректный запрос, а не отсутствующая запись.
	if _, err := svc.Push(ctx, userID, model.SecretRecord{Payload: []byte("x")}, 0); !errors.Is(err, service.ErrInvalidID) {
		t.Fatalf("пустой идентификатор дал %v, ожидалась ErrInvalidID", err)
	}
}

func TestPullReturnsChangesInOrder(t *testing.T) {
	ctx := t.Context()
	svc := newService()
	userID := register(t, svc)

	for _, id := range []string{"a", "b", "c"} {
		if _, err := svc.Push(ctx, userID, model.SecretRecord{ID: id, Payload: []byte(id)}, 0); err != nil {
			t.Fatalf("Push: %v", err)
		}
	}

	var revisions []int64
	for rec, err := range svc.Pull(ctx, userID, 1) {
		if err != nil {
			t.Fatalf("Pull: %v", err)
		}
		revisions = append(revisions, rec.Revision)
	}
	if len(revisions) != 2 {
		t.Fatalf("получено %d изменений, ожидалось 2", len(revisions))
	}
	if revisions[0] >= revisions[1] {
		t.Fatalf("изменения пришли не по возрастанию: %v", revisions)
	}
}

func TestPullStopsOnBreak(t *testing.T) {
	ctx := t.Context()
	svc := newService()
	userID := register(t, svc)

	for _, id := range []string{"a", "b"} {
		if _, err := svc.Push(ctx, userID, model.SecretRecord{ID: id, Payload: []byte(id)}, 0); err != nil {
			t.Fatalf("Push: %v", err)
		}
	}

	var seen int
	for _, err := range svc.Pull(ctx, userID, 0) {
		if err != nil {
			t.Fatalf("Pull: %v", err)
		}
		seen++
		break
	}
	if seen != 1 {
		t.Fatalf("после выхода из цикла получено %d изменений", seen)
	}
}

func TestGetHidesDeletedSecret(t *testing.T) {
	ctx := t.Context()
	svc := newService()
	userID := register(t, svc)

	revision, err := svc.Push(ctx, userID, model.SecretRecord{ID: "a", Payload: []byte("one")}, 0)
	if err != nil {
		t.Fatalf("Push: %v", err)
	}
	if _, err := svc.Get(ctx, userID, "a"); err != nil {
		t.Fatalf("Get: %v", err)
	}

	if _, err := svc.Push(ctx, userID, model.SecretRecord{ID: "a", Deleted: true}, revision); err != nil {
		t.Fatalf("Push удаления: %v", err)
	}
	if _, err := svc.Get(ctx, userID, "a"); !errors.Is(err, service.ErrNotFound) {
		t.Fatalf("удалённая запись дала %v, ожидалась ErrNotFound", err)
	}
	if _, err := svc.Get(ctx, userID, "absent"); !errors.Is(err, service.ErrNotFound) {
		t.Fatalf("отсутствующая запись дала %v, ожидалась ErrNotFound", err)
	}
}

func register(t *testing.T, svc *service.Service) string {
	t.Helper()

	if _, err := svc.Register(t.Context(), credentials(t, testLogin)); err != nil {
		t.Fatalf("Register: %v", err)
	}
	return firstUserID
}
