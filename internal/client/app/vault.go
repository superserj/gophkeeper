// Package app собирает сценарии клиента поверх локального хранилища и сервера.
package app

import (
	"context"
	"errors"
	"fmt"
	"sort"
	"time"

	"github.com/google/uuid"

	"github.com/superserj/gophkeeper/internal/client/localstore"
	"github.com/superserj/gophkeeper/internal/client/remote"
	"github.com/superserj/gophkeeper/internal/crypto"
	"github.com/superserj/gophkeeper/internal/model"
)

// UploadThreshold — размер, начиная с которого запись отправляется потоком,
// а не одним сообщением.
const UploadThreshold = 1 << 20

// Ошибки сценариев.
var (
	// ErrNotFound возвращается, когда записи нет в локальном хранилище.
	ErrNotFound = errors.New("secret not found")
	// ErrNotLoggedIn возвращается, когда в хранилище нет профиля пользователя.
	ErrNotLoggedIn = errors.New("not logged in, run register or login first")
)

// Vault — открытое хранилище одного пользователя.
//
// Ключ шифрования живёт только внутри структуры и только пока работает команда:
// на диск он не попадает ни в каком виде.
type Vault struct {
	store   *localstore.Store
	client  *remote.Client
	login   string
	dataKey []byte
}

// SecretInfo — строка списка записей.
type SecretInfo struct {
	ID        string
	Kind      model.SecretKind
	Name      string
	Meta      string
	UpdatedAt time.Time
	Pending   bool
}

// Conflict — запись, которую изменили и локально, и на сервере.
type Conflict struct {
	ID     string
	Local  *model.Secret
	Remote *model.Secret
}

// SyncResult — итог синхронизации.
type SyncResult struct {
	Pulled    int
	Pushed    int
	Conflicts []Conflict
}

// Register заводит пользователя: клиент генерирует соли, выводит ключи и
// отправляет серверу только производные значения.
func Register(ctx context.Context, client *remote.Client, store *localstore.Store, login, master string) (*Vault, error) {
	saltAuth, err := crypto.NewSalt()
	if err != nil {
		return nil, err
	}
	saltData, err := crypto.NewSalt()
	if err != nil {
		return nil, err
	}

	dataKey := crypto.DeriveDataKey(master, saltData)
	verifier, err := crypto.NewVerifier(dataKey, login)
	if err != nil {
		return nil, err
	}

	session, err := client.Register(ctx, remote.RegisterParams{
		Login:      login,
		AuthKey:    crypto.DeriveAuthKey(master, saltAuth),
		SaltAuth:   saltAuth,
		SaltData:   saltData,
		KDFVersion: crypto.KDFVersion,
		Verifier:   verifier,
	})
	if err != nil {
		return nil, err
	}

	return saveSession(client, store, login, master, session)
}

// Login входит на сервер и сохраняет профиль локально.
func Login(ctx context.Context, client *remote.Client, store *localstore.Store, login, master string) (*Vault, error) {
	saltAuth, _, err := client.Salts(ctx, login)
	if err != nil {
		return nil, err
	}

	session, err := client.Login(ctx, login, crypto.DeriveAuthKey(master, saltAuth))
	if err != nil {
		return nil, err
	}
	return saveSession(client, store, login, master, session)
}

// Unlock открывает локальное хранилище без обращения к серверу.
//
// Соли и верификатор лежат рядом с данными, поэтому офлайн доступен весь
// последний синхронизированный снимок.
func Unlock(client *remote.Client, store *localstore.Store, master string) (*Vault, error) {
	profile, err := store.Profile()
	if errors.Is(err, localstore.ErrNoProfile) {
		return nil, ErrNotLoggedIn
	}
	if err != nil {
		return nil, err
	}

	dataKey := crypto.DeriveDataKey(master, profile.SaltData)
	if err := crypto.CheckVerifier(dataKey, profile.Login, profile.Verifier); err != nil {
		return nil, err
	}

	if client != nil {
		token, err := store.Token()
		if err != nil {
			return nil, err
		}
		client.SetToken(token)
	}
	return &Vault{store: store, client: client, login: profile.Login, dataKey: dataKey}, nil
}

func saveSession(client *remote.Client, store *localstore.Store, login, master string, session remote.Session) (*Vault, error) {
	dataKey := crypto.DeriveDataKey(master, session.SaltData)
	if err := crypto.CheckVerifier(dataKey, login, session.Verifier); err != nil {
		return nil, err
	}

	err := store.SaveProfile(localstore.Profile{
		Login:      login,
		SaltAuth:   session.SaltAuth,
		SaltData:   session.SaltData,
		KDFVersion: session.KDFVersion,
		Verifier:   session.Verifier,
	})
	if err != nil {
		return nil, err
	}
	if err := store.SaveToken(session.Token); err != nil {
		return nil, err
	}
	client.SetToken(session.Token)

	return &Vault{store: store, client: client, login: login, dataKey: dataKey}, nil
}

// Add шифрует запись и кладёт её в очередь на отправку.
func (v *Vault) Add(secret *model.Secret) (string, error) {
	id := uuid.NewString()
	payload, err := v.seal(id, secret)
	if err != nil {
		return "", err
	}
	if len(payload) > model.MaxSecretSize {
		return "", fmt.Errorf("secret is larger than %d bytes", model.MaxSecretSize)
	}

	err = v.store.PutPending(localstore.PendingChange{
		ID:           id,
		Op:           localstore.OpPut,
		Payload:      payload,
		BaseRevision: 0,
	})
	if err != nil {
		return "", err
	}
	return id, nil
}

// Update перешифровывает существующую запись и ставит её в очередь на отправку.
func (v *Vault) Update(id string, secret *model.Secret) error {
	base, err := v.baseRevision(id)
	if err != nil {
		return err
	}
	payload, err := v.seal(id, secret)
	if err != nil {
		return err
	}
	return v.store.PutPending(localstore.PendingChange{
		ID:           id,
		Op:           localstore.OpPut,
		Payload:      payload,
		BaseRevision: base,
	})
}

// Delete помечает запись удалённой. Физически она исчезнет у всех клиентов
// только после синхронизации: сервер хранит отметку об удалении.
func (v *Vault) Delete(id string) error {
	base, err := v.baseRevision(id)
	if err != nil {
		return err
	}
	return v.store.PutPending(localstore.PendingChange{
		ID:           id,
		Op:           localstore.OpDelete,
		BaseRevision: base,
	})
}

// List возвращает записи: локальные изменения показываются поверх снимка сервера.
func (v *Vault) List() ([]SecretInfo, error) {
	records, err := v.store.ServerRecords()
	if err != nil {
		return nil, err
	}
	pending, err := v.store.PendingChanges()
	if err != nil {
		return nil, err
	}

	infos := make(map[string]SecretInfo, len(records))
	for _, rec := range records {
		if rec.Deleted {
			continue
		}
		info, err := v.info(rec.ID, rec.Payload, rec.UpdatedAt, false)
		if err != nil {
			return nil, err
		}
		infos[rec.ID] = info
	}

	for _, change := range pending {
		if change.Op == localstore.OpDelete {
			delete(infos, change.ID)
			continue
		}
		info, err := v.info(change.ID, change.Payload, time.Now(), true)
		if err != nil {
			return nil, err
		}
		infos[change.ID] = info
	}

	list := make([]SecretInfo, 0, len(infos))
	for _, info := range infos {
		list = append(list, info)
	}
	sort.Slice(list, func(i, j int) bool { return list[i].Name < list[j].Name })
	return list, nil
}

// Get расшифровывает запись по идентификатору.
func (v *Vault) Get(id string) (*model.Secret, error) {
	if change, found, err := v.store.Pending(id); err != nil {
		return nil, err
	} else if found {
		if change.Op == localstore.OpDelete {
			return nil, ErrNotFound
		}
		return v.open(id, change.Payload)
	}

	rec, found, err := v.store.ServerRecord(id)
	if err != nil {
		return nil, err
	}
	if !found || rec.Deleted {
		return nil, ErrNotFound
	}
	return v.open(id, rec.Payload)
}

// Sync забирает изменения сервера, затем отправляет свои.
//
// Порядок важен: Pull обновляет только снимок сервера и не трогает очередь
// локальных изменений, поэтому правка, сделанная офлайн, не теряется.
func (v *Vault) Sync(ctx context.Context) (SyncResult, error) {
	var result SyncResult

	since, err := v.store.LastRevision()
	if err != nil {
		return result, err
	}

	err = v.client.Pull(ctx, since, func(rec model.SecretRecord) error {
		if err := v.store.ApplyChange(rec); err != nil {
			return err
		}
		result.Pulled++
		return nil
	})
	if err != nil {
		return result, err
	}

	pending, err := v.store.PendingChanges()
	if err != nil {
		return result, err
	}

	for _, change := range pending {
		conflict, err := v.push(ctx, change)
		if err != nil {
			return result, err
		}
		if conflict != nil {
			result.Conflicts = append(result.Conflicts, *conflict)
			continue
		}
		result.Pushed++
	}
	return result, nil
}

// ResolveLocal отправляет локальную версию поверх серверной.
func (v *Vault) ResolveLocal(ctx context.Context, id string) error {
	change, found, err := v.store.Pending(id)
	if err != nil {
		return err
	}
	if !found {
		return ErrNotFound
	}

	rec, _, err := v.store.ServerRecord(id)
	if err != nil {
		return err
	}
	change.BaseRevision = rec.Revision

	conflict, err := v.push(ctx, change)
	if err != nil {
		return err
	}
	if conflict != nil {
		return errors.New("secret changed again during resolution, run sync once more")
	}
	return nil
}

// ResolveRemote отказывается от локальной версии в пользу серверной.
func (v *Vault) ResolveRemote(id string) error {
	return v.store.DropPending(id)
}

// Login возвращает логин владельца открытого хранилища.
func (v *Vault) Login() string {
	return v.login
}

func (v *Vault) push(ctx context.Context, change localstore.PendingChange) (*Conflict, error) {
	rec := model.SecretRecord{
		ID:      change.ID,
		Payload: change.Payload,
		Deleted: change.Op == localstore.OpDelete,
	}

	var (
		revision int64
		err      error
	)
	if len(rec.Payload) > UploadThreshold {
		revision, err = v.client.Upload(ctx, rec.ID, rec.Payload, change.BaseRevision)
	} else {
		revision, err = v.client.Push(ctx, rec, change.BaseRevision)
	}

	var conflict *remote.ConflictError
	if errors.As(err, &conflict) {
		return v.conflict(change, conflict)
	}
	if err != nil {
		return nil, err
	}

	rec.Revision = revision
	rec.UpdatedAt = time.Now()
	if err := v.store.PutServerRecord(rec); err != nil {
		return nil, err
	}
	return nil, v.store.DropPending(change.ID)
}

func (v *Vault) conflict(change localstore.PendingChange, conflict *remote.ConflictError) (*Conflict, error) {
	out := &Conflict{ID: change.ID}

	if change.Op == localstore.OpPut {
		local, err := v.open(change.ID, change.Payload)
		if err != nil {
			return nil, err
		}
		out.Local = local
	}
	if len(conflict.Current.Payload) > 0 && !conflict.Current.Deleted {
		current, err := v.open(change.ID, conflict.Current.Payload)
		if err != nil {
			return nil, err
		}
		out.Remote = current
	}
	if conflict.Current.ID != "" {
		if err := v.store.PutServerRecord(conflict.Current); err != nil {
			return nil, err
		}
	}
	return out, nil
}

func (v *Vault) baseRevision(id string) (int64, error) {
	if change, found, err := v.store.Pending(id); err != nil {
		return 0, err
	} else if found {
		return change.BaseRevision, nil
	}

	rec, found, err := v.store.ServerRecord(id)
	if err != nil {
		return 0, err
	}
	if !found {
		return 0, ErrNotFound
	}
	return rec.Revision, nil
}

func (v *Vault) seal(id string, secret *model.Secret) ([]byte, error) {
	plaintext, err := secret.Marshal()
	if err != nil {
		return nil, err
	}
	return crypto.Seal(v.dataKey, []byte(id), plaintext)
}

func (v *Vault) open(id string, payload []byte) (*model.Secret, error) {
	plaintext, err := crypto.Open(v.dataKey, []byte(id), payload)
	if err != nil {
		return nil, err
	}
	return model.UnmarshalSecret(plaintext)
}

func (v *Vault) info(id string, payload []byte, updatedAt time.Time, pending bool) (SecretInfo, error) {
	secret, err := v.open(id, payload)
	if err != nil {
		return SecretInfo{}, err
	}
	return SecretInfo{
		ID:        id,
		Kind:      secret.Kind,
		Name:      secret.Name,
		Meta:      secret.Meta,
		UpdatedAt: updatedAt,
		Pending:   pending,
	}, nil
}
