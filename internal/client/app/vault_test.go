package app_test

import (
	"context"
	"errors"
	"net"
	"path/filepath"
	"testing"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/test/bufconn"

	"github.com/superserj/gophkeeper/internal/client/app"
	"github.com/superserj/gophkeeper/internal/client/localstore"
	"github.com/superserj/gophkeeper/internal/client/remote"
	"github.com/superserj/gophkeeper/internal/crypto"
	"github.com/superserj/gophkeeper/internal/model"
	"github.com/superserj/gophkeeper/internal/server/auth"
	"github.com/superserj/gophkeeper/internal/server/grpcapi"
	"github.com/superserj/gophkeeper/internal/server/service"
	"github.com/superserj/gophkeeper/internal/server/storage/memory"
	pb "github.com/superserj/gophkeeper/proto/gophkeeper/v1"
)

const (
	bufSize    = 1024 * 1024
	testLogin  = "user"
	testMaster = "master password"
)

// startServer поднимает настоящий сервер поверх bufconn: тесты проходят весь путь
// от команды клиента до хранилища, но без сети и базы.
func startServer(t *testing.T) *bufconn.Listener {
	t.Helper()

	tokens := auth.NewTokenManager("test-secret", auth.TokenTTL)
	svc := service.New(memory.New(), tokens)

	server := grpc.NewServer(
		grpc.UnaryInterceptor(grpcapi.UnaryAuthInterceptor(tokens)),
		grpc.StreamInterceptor(grpcapi.StreamAuthInterceptor(tokens)),
	)
	pb.RegisterAuthServiceServer(server, grpcapi.NewAuthService(svc))
	pb.RegisterVaultServiceServer(server, grpcapi.NewVaultService(svc))

	listener := bufconn.Listen(bufSize)
	go func() {
		_ = server.Serve(listener)
	}()
	t.Cleanup(func() {
		server.Stop()
		_ = listener.Close()
	})
	return listener
}

func newClient(t *testing.T, listener *bufconn.Listener) *remote.Client {
	t.Helper()

	conn, err := grpc.NewClient("passthrough:///bufnet",
		grpc.WithContextDialer(func(ctx context.Context, _ string) (net.Conn, error) {
			return listener.DialContext(ctx)
		}),
		grpc.WithTransportCredentials(insecure.NewCredentials()),
	)
	if err != nil {
		t.Fatalf("grpc.NewClient: %v", err)
	}
	client := remote.Wrap(conn)
	t.Cleanup(func() {
		_ = client.Close()
	})
	return client
}

func newStore(t *testing.T) *localstore.Store {
	t.Helper()

	store, err := localstore.Open(filepath.Join(t.TempDir(), "vault.db"))
	if err != nil {
		t.Fatalf("localstore.Open: %v", err)
	}
	t.Cleanup(func() {
		_ = store.Close()
	})
	return store
}

func credentialsSecret(name, login, password string) *model.Secret {
	return &model.Secret{
		Kind:        model.KindCredentials,
		Name:        name,
		Credentials: &model.Credentials{Login: login, Password: password},
	}
}

func TestRegisterAddAndSync(t *testing.T) {
	ctx := t.Context()
	listener := startServer(t)

	vault, err := app.Register(ctx, newClient(t, listener), newStore(t), testLogin, testMaster)
	if err != nil {
		t.Fatalf("Register: %v", err)
	}

	id, err := vault.Add(credentialsSecret("bank", "user", "pass"))
	if err != nil {
		t.Fatalf("Add: %v", err)
	}

	list, err := vault.List()
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	if len(list) != 1 || !list[0].Pending {
		t.Fatalf("до синхронизации получен список %+v", list)
	}

	result, err := vault.Sync(ctx)
	if err != nil {
		t.Fatalf("Sync: %v", err)
	}
	if result.Pushed != 1 || len(result.Conflicts) != 0 {
		t.Fatalf("итог синхронизации %+v", result)
	}

	secret, err := vault.Get(id)
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if secret.Credentials.Password != "pass" {
		t.Fatalf("прочитан секрет %+v", secret)
	}
}

func TestSecondClientSeesSecrets(t *testing.T) {
	ctx := t.Context()
	listener := startServer(t)

	first, err := app.Register(ctx, newClient(t, listener), newStore(t), testLogin, testMaster)
	if err != nil {
		t.Fatalf("Register: %v", err)
	}
	if _, err := first.Add(credentialsSecret("bank", "user", "pass")); err != nil {
		t.Fatalf("Add: %v", err)
	}
	if _, err := first.Sync(ctx); err != nil {
		t.Fatalf("Sync: %v", err)
	}

	second, err := app.Login(ctx, newClient(t, listener), newStore(t), testLogin, testMaster)
	if err != nil {
		t.Fatalf("Login: %v", err)
	}
	result, err := second.Sync(ctx)
	if err != nil {
		t.Fatalf("Sync: %v", err)
	}
	if result.Pulled != 1 {
		t.Fatalf("второй клиент получил %d изменений", result.Pulled)
	}

	list, err := second.List()
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	if len(list) != 1 || list[0].Name != "bank" {
		t.Fatalf("второй клиент видит %+v", list)
	}
}

func TestOfflineEditSurvivesPull(t *testing.T) {
	ctx := t.Context()
	listener := startServer(t)

	firstStore, secondStore := newStore(t), newStore(t)
	first, err := app.Register(ctx, newClient(t, listener), firstStore, testLogin, testMaster)
	if err != nil {
		t.Fatalf("Register: %v", err)
	}
	id, err := first.Add(credentialsSecret("bank", "user", "pass"))
	if err != nil {
		t.Fatalf("Add: %v", err)
	}
	if _, err := first.Sync(ctx); err != nil {
		t.Fatalf("Sync: %v", err)
	}

	second, err := app.Login(ctx, newClient(t, listener), secondStore, testLogin, testMaster)
	if err != nil {
		t.Fatalf("Login: %v", err)
	}
	if _, err := second.Sync(ctx); err != nil {
		t.Fatalf("Sync: %v", err)
	}

	// Первый клиент правит запись и публикует её, второй правит ту же запись офлайн.
	if err := first.Update(id, credentialsSecret("bank", "user", "from-first")); err != nil {
		t.Fatalf("Update: %v", err)
	}
	if _, err := first.Sync(ctx); err != nil {
		t.Fatalf("Sync: %v", err)
	}
	if err := second.Update(id, credentialsSecret("bank", "user", "from-second")); err != nil {
		t.Fatalf("Update: %v", err)
	}

	result, err := second.Sync(ctx)
	if err != nil {
		t.Fatalf("Sync: %v", err)
	}
	if len(result.Conflicts) != 1 {
		t.Fatalf("ожидался один конфликт, получено %+v", result)
	}

	conflict := result.Conflicts[0]
	if conflict.Local.Credentials.Password != "from-second" {
		t.Fatalf("локальная версия потеряна: %+v", conflict.Local)
	}
	if conflict.Remote.Credentials.Password != "from-first" {
		t.Fatalf("серверная версия не показана: %+v", conflict.Remote)
	}

	// Локальная правка остаётся видимой до разрешения конфликта.
	secret, err := second.Get(id)
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if secret.Credentials.Password != "from-second" {
		t.Fatalf("после конфликта показана версия %q", secret.Credentials.Password)
	}
}

func TestResolveLocalPublishesOwnVersion(t *testing.T) {
	ctx := t.Context()
	listener := startServer(t)
	id, second, third := conflictingClients(t, listener)

	if err := second.ResolveLocal(ctx, id); err != nil {
		t.Fatalf("ResolveLocal: %v", err)
	}
	if _, err := third.Sync(ctx); err != nil {
		t.Fatalf("Sync: %v", err)
	}

	secret, err := third.Get(id)
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if secret.Credentials.Password != "from-second" {
		t.Fatalf("на сервере осталась версия %q", secret.Credentials.Password)
	}
}

func TestResolveRemoteDropsLocalVersion(t *testing.T) {
	listener := startServer(t)
	id, second, _ := conflictingClients(t, listener)

	if err := second.ResolveRemote(id); err != nil {
		t.Fatalf("ResolveRemote: %v", err)
	}

	secret, err := second.Get(id)
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if secret.Credentials.Password != "from-first" {
		t.Fatalf("после отказа от своей версии показана %q", secret.Credentials.Password)
	}
}

// conflictingClients доводит двух клиентов до конфликта по одной записи и
// возвращает её идентификатор, конфликтующего клиента и ещё один чистый клиент.
func conflictingClients(t *testing.T, listener *bufconn.Listener) (string, *app.Vault, *app.Vault) {
	t.Helper()
	ctx := t.Context()

	first, err := app.Register(ctx, newClient(t, listener), newStore(t), testLogin, testMaster)
	if err != nil {
		t.Fatalf("Register: %v", err)
	}
	id, err := first.Add(credentialsSecret("bank", "user", "pass"))
	if err != nil {
		t.Fatalf("Add: %v", err)
	}
	if _, err := first.Sync(ctx); err != nil {
		t.Fatalf("Sync: %v", err)
	}

	second, err := app.Login(ctx, newClient(t, listener), newStore(t), testLogin, testMaster)
	if err != nil {
		t.Fatalf("Login: %v", err)
	}
	if _, err := second.Sync(ctx); err != nil {
		t.Fatalf("Sync: %v", err)
	}

	if err := first.Update(id, credentialsSecret("bank", "user", "from-first")); err != nil {
		t.Fatalf("Update: %v", err)
	}
	if _, err := first.Sync(ctx); err != nil {
		t.Fatalf("Sync: %v", err)
	}
	if err := second.Update(id, credentialsSecret("bank", "user", "from-second")); err != nil {
		t.Fatalf("Update: %v", err)
	}
	if _, err := second.Sync(ctx); err != nil {
		t.Fatalf("Sync: %v", err)
	}

	third, err := app.Login(ctx, newClient(t, listener), newStore(t), testLogin, testMaster)
	if err != nil {
		t.Fatalf("Login: %v", err)
	}
	return id, second, third
}

func TestDeleteHidesSecretEverywhere(t *testing.T) {
	ctx := t.Context()
	listener := startServer(t)

	first, err := app.Register(ctx, newClient(t, listener), newStore(t), testLogin, testMaster)
	if err != nil {
		t.Fatalf("Register: %v", err)
	}
	id, err := first.Add(credentialsSecret("bank", "user", "pass"))
	if err != nil {
		t.Fatalf("Add: %v", err)
	}
	if _, err := first.Sync(ctx); err != nil {
		t.Fatalf("Sync: %v", err)
	}

	second, err := app.Login(ctx, newClient(t, listener), newStore(t), testLogin, testMaster)
	if err != nil {
		t.Fatalf("Login: %v", err)
	}
	if _, err := second.Sync(ctx); err != nil {
		t.Fatalf("Sync: %v", err)
	}

	if err := first.Delete(id); err != nil {
		t.Fatalf("Delete: %v", err)
	}
	if _, err := first.Get(id); !errors.Is(err, app.ErrNotFound) {
		t.Fatalf("удалённая запись видна локально: %v", err)
	}
	if _, err := first.Sync(ctx); err != nil {
		t.Fatalf("Sync: %v", err)
	}

	if _, err := second.Sync(ctx); err != nil {
		t.Fatalf("Sync: %v", err)
	}
	if _, err := second.Get(id); !errors.Is(err, app.ErrNotFound) {
		t.Fatalf("удаление не доехало до второго клиента: %v", err)
	}
}

func TestBinarySecretGoesThroughUpload(t *testing.T) {
	ctx := t.Context()
	listener := startServer(t)

	vault, err := app.Register(ctx, newClient(t, listener), newStore(t), testLogin, testMaster)
	if err != nil {
		t.Fatalf("Register: %v", err)
	}

	payload := make([]byte, app.UploadThreshold+1)
	for i := range payload {
		payload[i] = byte(i % 251)
	}
	id, err := vault.Add(&model.Secret{Kind: model.KindBinary, Name: "archive", Binary: payload})
	if err != nil {
		t.Fatalf("Add: %v", err)
	}
	if _, err := vault.Sync(ctx); err != nil {
		t.Fatalf("Sync: %v", err)
	}

	second, err := app.Login(ctx, newClient(t, listener), newStore(t), testLogin, testMaster)
	if err != nil {
		t.Fatalf("Login: %v", err)
	}
	if _, err := second.Sync(ctx); err != nil {
		t.Fatalf("Sync: %v", err)
	}

	secret, err := second.Get(id)
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if len(secret.Binary) != len(payload) || secret.Binary[7] != payload[7] {
		t.Fatalf("бинарные данные доехали повреждёнными: %d байт", len(secret.Binary))
	}
}

func TestUnlockChecksMasterPassword(t *testing.T) {
	ctx := t.Context()
	listener := startServer(t)
	store := newStore(t)

	if _, err := app.Register(ctx, newClient(t, listener), store, testLogin, testMaster); err != nil {
		t.Fatalf("Register: %v", err)
	}

	if _, err := app.Unlock(newClient(t, listener), store, "wrong password"); !errors.Is(err, crypto.ErrWrongPassword) {
		t.Fatalf("опечатка в пароле дала %v, ожидалась ErrWrongPassword", err)
	}
	if _, err := app.Unlock(newClient(t, listener), store, testMaster); err != nil {
		t.Fatalf("правильный пароль не открыл хранилище: %v", err)
	}
}

func TestStoreBelongsToSingleAccount(t *testing.T) {
	ctx := t.Context()
	listener := startServer(t)
	store := newStore(t)

	if _, err := app.Register(ctx, newClient(t, listener), store, testLogin, testMaster); err != nil {
		t.Fatalf("Register: %v", err)
	}
	if _, err := app.Register(ctx, newClient(t, listener), newStore(t), "other", testMaster); err != nil {
		t.Fatalf("Register второго пользователя: %v", err)
	}

	// Вход другого владельца в чужое хранилище отправил бы его записи не тому аккаунту.
	_, err := app.Login(ctx, newClient(t, listener), store, "other", testMaster)
	if !errors.Is(err, app.ErrForeignStore) {
		t.Fatalf("получено %v, ожидалась ErrForeignStore", err)
	}

	// Повторный вход того же владельца по-прежнему разрешён.
	if _, err := app.Login(ctx, newClient(t, listener), store, testLogin, testMaster); err != nil {
		t.Fatalf("повторный вход владельца: %v", err)
	}
}

func TestUnlockWithoutProfile(t *testing.T) {
	listener := startServer(t)

	if _, err := app.Unlock(newClient(t, listener), newStore(t), testMaster); !errors.Is(err, app.ErrNotLoggedIn) {
		t.Fatalf("получено %v, ожидалась ErrNotLoggedIn", err)
	}
}

func TestLoginRejectsWrongPassword(t *testing.T) {
	ctx := t.Context()
	listener := startServer(t)

	if _, err := app.Register(ctx, newClient(t, listener), newStore(t), testLogin, testMaster); err != nil {
		t.Fatalf("Register: %v", err)
	}
	_, err := app.Login(ctx, newClient(t, listener), newStore(t), testLogin, "wrong password")
	if !errors.Is(err, remote.ErrBadCredentials) {
		t.Fatalf("получено %v, ожидалась ErrBadCredentials", err)
	}
}

func TestRegisterRejectsTakenLogin(t *testing.T) {
	ctx := t.Context()
	listener := startServer(t)

	if _, err := app.Register(ctx, newClient(t, listener), newStore(t), testLogin, testMaster); err != nil {
		t.Fatalf("Register: %v", err)
	}
	_, err := app.Register(ctx, newClient(t, listener), newStore(t), testLogin, testMaster)
	if !errors.Is(err, remote.ErrLoginTaken) {
		t.Fatalf("получено %v, ожидалась ErrLoginTaken", err)
	}
}

func TestUpdateAndDeleteRequireExistingSecret(t *testing.T) {
	ctx := t.Context()
	listener := startServer(t)

	vault, err := app.Register(ctx, newClient(t, listener), newStore(t), testLogin, testMaster)
	if err != nil {
		t.Fatalf("Register: %v", err)
	}

	if err := vault.Update("absent", credentialsSecret("bank", "user", "pass")); !errors.Is(err, app.ErrNotFound) {
		t.Fatalf("Update дал %v, ожидалась ErrNotFound", err)
	}
	if err := vault.Delete("absent"); !errors.Is(err, app.ErrNotFound) {
		t.Fatalf("Delete дал %v, ожидалась ErrNotFound", err)
	}
	if _, err := vault.Get("absent"); !errors.Is(err, app.ErrNotFound) {
		t.Fatalf("Get дал %v, ожидалась ErrNotFound", err)
	}
}

func TestAddRejectsInvalidSecret(t *testing.T) {
	ctx := t.Context()
	listener := startServer(t)

	vault, err := app.Register(ctx, newClient(t, listener), newStore(t), testLogin, testMaster)
	if err != nil {
		t.Fatalf("Register: %v", err)
	}
	if _, err := vault.Add(&model.Secret{Kind: model.KindText, Name: "note"}); err == nil {
		t.Fatal("принята запись без содержимого")
	}
}

func TestSecretLargerThanLimitIsRejected(t *testing.T) {
	ctx := t.Context()
	listener := startServer(t)

	vault, err := app.Register(ctx, newClient(t, listener), newStore(t), testLogin, testMaster)
	if err != nil {
		t.Fatalf("Register: %v", err)
	}
	id, err := vault.Add(&model.Secret{Kind: model.KindBinary, Name: "small", Binary: []byte{1, 2, 3}})
	if err != nil {
		t.Fatalf("Add: %v", err)
	}

	// Слишком большая запись не должна оседать в очереди: иначе каждая следующая
	// синхронизация спотыкалась бы на ней.
	huge := &model.Secret{Kind: model.KindBinary, Name: "huge", Binary: make([]byte, model.MaxSecretSize)}
	if _, err := vault.Add(huge); err == nil {
		t.Fatal("Add принял запись больше лимита")
	}
	if err := vault.Update(id, huge); err == nil {
		t.Fatal("Update принял запись больше лимита")
	}

	if _, err := vault.Sync(ctx); err != nil {
		t.Fatalf("синхронизация после отказа: %v", err)
	}
}

func TestVaultLogin(t *testing.T) {
	ctx := t.Context()
	listener := startServer(t)

	vault, err := app.Register(ctx, newClient(t, listener), newStore(t), testLogin, testMaster)
	if err != nil {
		t.Fatalf("Register: %v", err)
	}
	if vault.Login() != testLogin {
		t.Fatalf("Login() вернул %q", vault.Login())
	}
}

func TestVaultRequiresToken(t *testing.T) {
	ctx := t.Context()
	listener := startServer(t)
	store := newStore(t)

	if _, err := app.Register(ctx, newClient(t, listener), store, testLogin, testMaster); err != nil {
		t.Fatalf("Register: %v", err)
	}

	// Хранилище с забытым токеном: сервер должен отказать в синхронизации.
	if err := store.SaveToken(""); err != nil {
		t.Fatalf("SaveToken: %v", err)
	}
	vault, err := app.Unlock(newClient(t, listener), store, testMaster)
	if err != nil {
		t.Fatalf("Unlock: %v", err)
	}
	if _, err := vault.Sync(ctx); !errors.Is(err, remote.ErrBadCredentials) {
		t.Fatalf("синхронизация без токена дала %v", err)
	}
}
