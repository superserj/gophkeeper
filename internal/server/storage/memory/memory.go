// Package memory хранит пользователей и записи в памяти процесса.
//
// Реализация повторяет семантику PostgreSQL-хранилища, включая нумерацию ревизий
// и обнаружение конфликтов, и используется в тестах, где поднимать базу избыточно.
package memory

import (
	"cmp"
	"context"
	"iter"
	"slices"
	"strconv"
	"sync"
	"time"

	"github.com/superserj/gophkeeper/internal/model"
	"github.com/superserj/gophkeeper/internal/server/storage"
)

// Storage — потокобезопасное хранилище в памяти.
type Storage struct {
	mu       sync.RWMutex
	nextID   int64
	users    map[string]*userState
	byUserID map[string]*userState
}

type userState struct {
	user     storage.User
	revision int64
	secrets  map[string]model.SecretRecord
}

// New создаёт пустое хранилище.
func New() *Storage {
	return &Storage{
		users:    make(map[string]*userState),
		byUserID: make(map[string]*userState),
	}
}

// CreateUser заводит пользователя.
func (s *Storage) CreateUser(_ context.Context, u storage.User) (string, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	if _, ok := s.users[u.Login]; ok {
		return "", storage.ErrLoginTaken
	}

	s.nextID++
	u.ID = strconv.FormatInt(s.nextID, 10)
	state := &userState{user: u, secrets: make(map[string]model.SecretRecord)}
	s.users[u.Login] = state
	s.byUserID[u.ID] = state
	return u.ID, nil
}

// GetUserByLogin возвращает профиль пользователя.
func (s *Storage) GetUserByLogin(_ context.Context, login string) (storage.User, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	state, ok := s.users[login]
	if !ok {
		return storage.User{}, storage.ErrUserNotFound
	}
	return state.user, nil
}

// GetSecret возвращает запись пользователя.
func (s *Storage) GetSecret(_ context.Context, userID, id string) (model.SecretRecord, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	state, ok := s.byUserID[userID]
	if !ok {
		return model.SecretRecord{}, storage.ErrUserNotFound
	}
	rec, ok := state.secrets[id]
	if !ok {
		return model.SecretRecord{}, storage.ErrSecretNotFound
	}
	return rec, nil
}

// EachSecretSince отдаёт изменения пользователя по возрастанию ревизии.
func (s *Storage) EachSecretSince(_ context.Context, userID string, since int64) iter.Seq2[model.SecretRecord, error] {
	return func(yield func(model.SecretRecord, error) bool) {
		s.mu.RLock()
		state, ok := s.byUserID[userID]
		if !ok {
			s.mu.RUnlock()
			yield(model.SecretRecord{}, storage.ErrUserNotFound)
			return
		}

		changes := make([]model.SecretRecord, 0, len(state.secrets))
		for _, rec := range state.secrets {
			if rec.Revision > since {
				changes = append(changes, rec)
			}
		}
		s.mu.RUnlock()

		slices.SortFunc(changes, func(a, b model.SecretRecord) int {
			return cmp.Compare(a.Revision, b.Revision)
		})
		for _, rec := range changes {
			if !yield(rec, nil) {
				return
			}
		}
	}
}

// SaveSecret сохраняет запись поверх известной клиенту ревизии.
func (s *Storage) SaveSecret(_ context.Context, userID string, rec model.SecretRecord, baseRevision int64) (int64, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	state, ok := s.byUserID[userID]
	if !ok {
		return 0, storage.ErrUserNotFound
	}

	current, exists := state.secrets[rec.ID]
	switch {
	case !exists && baseRevision != 0:
		return 0, &storage.ConflictError{}
	case exists && current.Revision != baseRevision:
		return 0, &storage.ConflictError{Current: current}
	}

	state.revision++
	rec.Revision = state.revision
	rec.UpdatedAt = time.Now()
	state.secrets[rec.ID] = rec
	return rec.Revision, nil
}
