// Package localstore хранит на диске зашифрованные записи и состояние синхронизации.
//
// Хранилище разделено на три части: server — последний известный снимок сервера,
// pending — локальные изменения, которые ещё не приняты сервером, meta — профиль,
// токен и курсор синхронизации. Разделение принципиально: иначе Pull затирал бы
// правки, сделанные офлайн.
package localstore

import (
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"time"

	bolt "go.etcd.io/bbolt"

	"github.com/superserj/gophkeeper/internal/model"
)

// Имена бакетов.
var (
	bucketServer  = []byte("server")
	bucketPending = []byte("pending")
	bucketMeta    = []byte("meta")
)

// Ключи бакета meta.
var (
	keyProfile      = []byte("profile")
	keyToken        = []byte("token")
	keyLastRevision = []byte("last_revision")
)

// Права доступа к файлам хранилища: секреты читает только владелец.
const (
	dirPerm  = 0o700
	filePerm = 0o600
)

// openTimeout ограничивает ожидание блокировки файла, если второй экземпляр
// клиента уже открыл то же хранилище.
const openTimeout = 2 * time.Second

// ErrNoProfile возвращается, когда в хранилище ещё нет профиля пользователя.
var ErrNoProfile = errors.New("profile is not saved")

// Profile — то, что нужно знать клиенту, чтобы вывести ключи и проверить пароль.
type Profile struct {
	Login      string `json:"login"`
	SaltAuth   []byte `json:"salt_auth"`
	SaltData   []byte `json:"salt_data"`
	KDFVersion uint32 `json:"kdf_version"`
	Verifier   []byte `json:"verifier"`
}

// PendingOp — вид локального изменения.
type PendingOp string

// Виды локальных изменений.
const (
	// OpPut — создание или изменение записи.
	OpPut PendingOp = "put"
	// OpDelete — удаление записи.
	OpDelete PendingOp = "delete"
)

// PendingChange — локальное изменение вместе с ревизией, поверх которой оно сделано.
type PendingChange struct {
	ID           string    `json:"id"`
	Op           PendingOp `json:"op"`
	Payload      []byte    `json:"payload,omitempty"`
	BaseRevision int64     `json:"base_revision"`
}

// storedRecord — запись серверного снимка на диске.
type storedRecord struct {
	Payload   []byte    `json:"payload,omitempty"`
	Deleted   bool      `json:"deleted"`
	Revision  int64     `json:"revision"`
	UpdatedAt time.Time `json:"updated_at"`
}

// Store — файловое хранилище клиента.
type Store struct {
	db *bolt.DB
}

// Open открывает или создаёт хранилище по пути path.
func Open(path string) (*Store, error) {
	if err := os.MkdirAll(filepath.Dir(path), dirPerm); err != nil {
		return nil, fmt.Errorf("create store directory: %w", err)
	}

	db, err := bolt.Open(path, filePerm, &bolt.Options{Timeout: openTimeout})
	if err != nil {
		return nil, fmt.Errorf("open store: %w", err)
	}

	// Права применяются только при создании файла, а в хранилище лежат токен и
	// шифротексты: заранее созданный файл с правами 0644 отдал бы их всем.
	if err := os.Chmod(path, filePerm); err != nil {
		_ = db.Close()
		return nil, fmt.Errorf("restrict store permissions: %w", err)
	}

	err = db.Update(func(tx *bolt.Tx) error {
		for _, name := range [][]byte{bucketServer, bucketPending, bucketMeta} {
			if _, err := tx.CreateBucketIfNotExists(name); err != nil {
				return fmt.Errorf("create bucket %s: %w", name, err)
			}
		}
		return nil
	})
	if err != nil {
		_ = db.Close()
		return nil, err
	}
	return &Store{db: db}, nil
}

// Close закрывает файл хранилища.
func (s *Store) Close() error {
	return s.db.Close()
}

// SaveProfile сохраняет профиль пользователя.
func (s *Store) SaveProfile(p Profile) error {
	data, err := json.Marshal(p)
	if err != nil {
		return fmt.Errorf("marshal profile: %w", err)
	}
	return s.db.Update(func(tx *bolt.Tx) error {
		return tx.Bucket(bucketMeta).Put(keyProfile, data)
	})
}

// Profile возвращает сохранённый профиль.
func (s *Store) Profile() (Profile, error) {
	var p Profile
	err := s.db.View(func(tx *bolt.Tx) error {
		data := tx.Bucket(bucketMeta).Get(keyProfile)
		if data == nil {
			return ErrNoProfile
		}
		return json.Unmarshal(data, &p)
	})
	return p, err
}

// SaveToken сохраняет токен доступа.
func (s *Store) SaveToken(token string) error {
	return s.db.Update(func(tx *bolt.Tx) error {
		return tx.Bucket(bucketMeta).Put(keyToken, []byte(token))
	})
}

// Token возвращает сохранённый токен доступа.
func (s *Store) Token() (string, error) {
	var token string
	err := s.db.View(func(tx *bolt.Tx) error {
		token = string(tx.Bucket(bucketMeta).Get(keyToken))
		return nil
	})
	return token, err
}

// LastRevision возвращает курсор синхронизации.
func (s *Store) LastRevision() (int64, error) {
	var revision int64
	err := s.db.View(func(tx *bolt.Tx) error {
		if data := tx.Bucket(bucketMeta).Get(keyLastRevision); len(data) == 8 {
			revision = int64(binary.BigEndian.Uint64(data))
		}
		return nil
	})
	return revision, err
}

// ApplyChange записывает изменение с сервера и сдвигает курсор в одной транзакции.
//
// Атомарность здесь и есть смысл метода: если сохранить запись, но потерять курсор
// (или наоборот), после обрыва связи клиент либо применит изменение дважды, либо
// никогда не увидит более раннюю ревизию, которую не успел получить.
func (s *Store) ApplyChange(rec model.SecretRecord) error {
	stored, err := json.Marshal(storedRecord{
		Payload:   rec.Payload,
		Deleted:   rec.Deleted,
		Revision:  rec.Revision,
		UpdatedAt: rec.UpdatedAt,
	})
	if err != nil {
		return fmt.Errorf("marshal record: %w", err)
	}

	return s.db.Update(func(tx *bolt.Tx) error {
		if err := tx.Bucket(bucketServer).Put([]byte(rec.ID), stored); err != nil {
			return fmt.Errorf("put record: %w", err)
		}
		cursor := make([]byte, 8)
		binary.BigEndian.PutUint64(cursor, uint64(rec.Revision))
		return tx.Bucket(bucketMeta).Put(keyLastRevision, cursor)
	})
}

// PutServerRecord сохраняет запись снимка, не трогая курсор синхронизации.
//
// Так применяется результат собственного Push: ревизия записи уже известна, но
// между курсором и ею могли остаться изменения других клиентов, поэтому двигать
// курсор нельзя — их нужно получить следующим Pull.
func (s *Store) PutServerRecord(rec model.SecretRecord) error {
	stored, err := json.Marshal(storedRecord{
		Payload:   rec.Payload,
		Deleted:   rec.Deleted,
		Revision:  rec.Revision,
		UpdatedAt: rec.UpdatedAt,
	})
	if err != nil {
		return fmt.Errorf("marshal record: %w", err)
	}
	return s.db.Update(func(tx *bolt.Tx) error {
		return tx.Bucket(bucketServer).Put([]byte(rec.ID), stored)
	})
}

// CommitPushed переносит принятую сервером запись из очереди в снимок одной
// транзакцией: раздельные записи оставили бы подтверждённое изменение в очереди,
// и следующая синхронизация отправила бы его повторно — уже как конфликт.
func (s *Store) CommitPushed(rec model.SecretRecord) error {
	stored, err := json.Marshal(storedRecord{
		Payload:   rec.Payload,
		Deleted:   rec.Deleted,
		Revision:  rec.Revision,
		UpdatedAt: rec.UpdatedAt,
	})
	if err != nil {
		return fmt.Errorf("marshal record: %w", err)
	}

	return s.db.Update(func(tx *bolt.Tx) error {
		if err := tx.Bucket(bucketServer).Put([]byte(rec.ID), stored); err != nil {
			return fmt.Errorf("put record: %w", err)
		}
		return tx.Bucket(bucketPending).Delete([]byte(rec.ID))
	})
}

// ServerRecord возвращает запись снимка по идентификатору.
func (s *Store) ServerRecord(id string) (model.SecretRecord, bool, error) {
	var (
		rec   model.SecretRecord
		found bool
	)
	err := s.db.View(func(tx *bolt.Tx) error {
		data := tx.Bucket(bucketServer).Get([]byte(id))
		if data == nil {
			return nil
		}
		var stored storedRecord
		if err := json.Unmarshal(data, &stored); err != nil {
			return fmt.Errorf("unmarshal record: %w", err)
		}
		rec = model.SecretRecord{
			ID:        id,
			Payload:   stored.Payload,
			Deleted:   stored.Deleted,
			Revision:  stored.Revision,
			UpdatedAt: stored.UpdatedAt,
		}
		found = true
		return nil
	})
	return rec, found, err
}

// ServerRecords возвращает весь снимок сервера, включая удалённые записи.
func (s *Store) ServerRecords() ([]model.SecretRecord, error) {
	var records []model.SecretRecord
	err := s.db.View(func(tx *bolt.Tx) error {
		return tx.Bucket(bucketServer).ForEach(func(key, value []byte) error {
			var stored storedRecord
			if err := json.Unmarshal(value, &stored); err != nil {
				return fmt.Errorf("unmarshal record: %w", err)
			}
			records = append(records, model.SecretRecord{
				ID:        string(key),
				Payload:   stored.Payload,
				Deleted:   stored.Deleted,
				Revision:  stored.Revision,
				UpdatedAt: stored.UpdatedAt,
			})
			return nil
		})
	})
	return records, err
}

// PutPending сохраняет локальное изменение.
func (s *Store) PutPending(change PendingChange) error {
	data, err := json.Marshal(change)
	if err != nil {
		return fmt.Errorf("marshal pending change: %w", err)
	}
	return s.db.Update(func(tx *bolt.Tx) error {
		return tx.Bucket(bucketPending).Put([]byte(change.ID), data)
	})
}

// Pending возвращает локальное изменение по идентификатору записи.
func (s *Store) Pending(id string) (PendingChange, bool, error) {
	var (
		change PendingChange
		found  bool
	)
	err := s.db.View(func(tx *bolt.Tx) error {
		data := tx.Bucket(bucketPending).Get([]byte(id))
		if data == nil {
			return nil
		}
		found = true
		return json.Unmarshal(data, &change)
	})
	return change, found, err
}

// PendingChanges возвращает все неотправленные изменения.
func (s *Store) PendingChanges() ([]PendingChange, error) {
	var changes []PendingChange
	err := s.db.View(func(tx *bolt.Tx) error {
		return tx.Bucket(bucketPending).ForEach(func(_, value []byte) error {
			var change PendingChange
			if err := json.Unmarshal(value, &change); err != nil {
				return fmt.Errorf("unmarshal pending change: %w", err)
			}
			changes = append(changes, change)
			return nil
		})
	})
	return changes, err
}

// DropPending удаляет локальное изменение после того, как сервер его принял
// или пользователь отказался от своей версии.
func (s *Store) DropPending(id string) error {
	return s.db.Update(func(tx *bolt.Tx) error {
		return tx.Bucket(bucketPending).Delete([]byte(id))
	})
}
