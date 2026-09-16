// Package service содержит бизнес-логику сервера: регистрацию, вход и работу с записями.
package service

import (
	"context"
	"errors"
	"fmt"
	"iter"

	"golang.org/x/sync/semaphore"

	"github.com/superserj/gophkeeper/internal/crypto"
	"github.com/superserj/gophkeeper/internal/model"
	"github.com/superserj/gophkeeper/internal/server/auth"
	"github.com/superserj/gophkeeper/internal/server/storage"
)

// Ограничения на запросы, доступные без токена.
const (
	// maxParallelKDF — сколько вычислений Argon2id идут одновременно: каждое
	// занимает 64 МиБ памяти.
	maxParallelKDF = 4
	// maxPendingKDF — сколько запросов ждут своей очереди. Ожидающий запрос
	// держит в памяти своё тело, поэтому очередь тоже ограничена: при перегрузке
	// сервер честно отказывает вместо того, чтобы копить запросы до отказа памяти.
	maxPendingKDF = 32
	// MaxLoginLength — предел длины логина. Совпадает с шириной колонки login
	// в схеме базы: длиннее всё равно не сохранится.
	MaxLoginLength = 64
	// MaxVerifierSize — предел размера верификатора: он шифрует короткую
	// контрольную строку, и больше этого значения там быть нечему.
	MaxVerifierSize = 256
)

// Repository — доступ к хранилищу, нужный сервису.
type Repository interface {
	CreateUser(ctx context.Context, u storage.User) (string, error)
	GetUserByLogin(ctx context.Context, login string) (storage.User, error)
	GetSecret(ctx context.Context, userID, id string) (model.SecretRecord, error)
	EachSecretSince(ctx context.Context, userID string, since int64) iter.Seq2[model.SecretRecord, error]
	SaveSecret(ctx context.Context, userID string, rec model.SecretRecord, baseRevision int64) (int64, error)
}

// Ошибки сервиса.
var (
	// ErrLoginTaken возвращается при регистрации занятого логина.
	ErrLoginTaken = errors.New("login already taken")
	// ErrBadCredentials возвращается при неверной паре логин/ключ.
	ErrBadCredentials = errors.New("invalid credentials")
	// ErrNotFound возвращается, когда записи нет.
	ErrNotFound = errors.New("not found")
	// ErrPayloadTooLarge возвращается, когда запись больше model.MaxSecretSize.
	ErrPayloadTooLarge = errors.New("payload too large")
	// ErrEmptyLogin возвращается на пустой логин.
	ErrEmptyLogin = errors.New("login is empty")
	// ErrBusy возвращается, когда очередь на вывод ключей переполнена.
	ErrBusy = errors.New("server is busy")
	// ErrInvalidID возвращается на пустой идентификатор записи: это неверно
	// сформированный запрос, а не отсутствующий ресурс.
	ErrInvalidID = errors.New("secret id is empty")
)

// Credentials — данные, которые клиент присылает при регистрации.
//
// Соли и верификатор генерирует клиент: сервер хранит их как непрозрачные значения
// и выдаёт обратно, чтобы второй клиент того же владельца смог вывести те же ключи.
type Credentials struct {
	Login      string
	AuthKey    []byte
	SaltAuth   []byte
	SaltData   []byte
	KDFVersion uint32
	Verifier   []byte
}

// Session — результат регистрации или входа.
type Session struct {
	Token      string
	SaltAuth   []byte
	SaltData   []byte
	KDFVersion uint32
	Verifier   []byte
}

// Salts — то, что клиент получает до аутентификации, чтобы вывести authKey.
type Salts struct {
	SaltAuth   []byte
	KDFVersion uint32
}

// Service реализует сценарии сервера поверх репозитория и менеджера токенов.
type Service struct {
	repo    Repository
	tokens  *auth.TokenManager
	kdf     *semaphore.Weighted
	pending *semaphore.Weighted
}

// New создаёт сервис.
func New(repo Repository, tokens *auth.TokenManager) *Service {
	return &Service{
		repo:    repo,
		tokens:  tokens,
		kdf:     semaphore.NewWeighted(maxParallelKDF),
		pending: semaphore.NewWeighted(maxPendingKDF),
	}
}

// Register заводит пользователя и сразу выдаёт токен.
func (s *Service) Register(ctx context.Context, c Credentials) (Session, error) {
	if c.Login == "" {
		return Session{}, ErrEmptyLogin
	}
	if len(c.Login) > MaxLoginLength {
		return Session{}, ErrBadCredentials
	}
	// Размеры фиксированы схемой: всё, что больше, — попытка занять память сервера.
	if len(c.AuthKey) != crypto.KeySize || len(c.SaltAuth) != crypto.SaltSize || len(c.SaltData) != crypto.SaltSize {
		return Session{}, ErrBadCredentials
	}
	if len(c.Verifier) == 0 || len(c.Verifier) > MaxVerifierSize {
		return Session{}, ErrBadCredentials
	}

	release, err := s.acquireKDF(ctx)
	if err != nil {
		return Session{}, err
	}
	hash, err := auth.HashAuthKey(c.AuthKey)
	release()
	if err != nil {
		return Session{}, fmt.Errorf("hash auth key: %w", err)
	}

	userID, err := s.repo.CreateUser(ctx, storage.User{
		Login:        c.Login,
		PasswordHash: hash,
		SaltAuth:     c.SaltAuth,
		SaltData:     c.SaltData,
		KDFVersion:   c.KDFVersion,
		Verifier:     c.Verifier,
	})
	if errors.Is(err, storage.ErrLoginTaken) {
		return Session{}, ErrLoginTaken
	}
	if err != nil {
		return Session{}, err
	}

	token, err := s.tokens.Issue(userID)
	if err != nil {
		return Session{}, err
	}
	return Session{
		Token:      token,
		SaltAuth:   c.SaltAuth,
		SaltData:   c.SaltData,
		KDFVersion: c.KDFVersion,
		Verifier:   c.Verifier,
	}, nil
}

// Salts отдаёт соль аутентификации по логину. Она не секрет: без мастер-пароля
// из неё ничего не вывести, а клиенту она нужна до входа.
func (s *Service) Salts(ctx context.Context, login string) (Salts, error) {
	user, err := s.repo.GetUserByLogin(ctx, login)
	if errors.Is(err, storage.ErrUserNotFound) {
		return Salts{}, ErrBadCredentials
	}
	if err != nil {
		return Salts{}, err
	}
	return Salts{SaltAuth: user.SaltAuth, KDFVersion: user.KDFVersion}, nil
}

// Login проверяет ключ аутентификации и выдаёт токен.
func (s *Service) Login(ctx context.Context, login string, authKey []byte) (Session, error) {
	if login == "" || len(login) > MaxLoginLength || len(authKey) != crypto.KeySize {
		return Session{}, ErrBadCredentials
	}

	user, err := s.repo.GetUserByLogin(ctx, login)
	if errors.Is(err, storage.ErrUserNotFound) {
		return Session{}, ErrBadCredentials
	}
	if err != nil {
		return Session{}, err
	}

	release, err := s.acquireKDF(ctx)
	if err != nil {
		return Session{}, err
	}
	err = auth.VerifyAuthKey(user.PasswordHash, authKey)
	release()
	if err != nil {
		return Session{}, ErrBadCredentials
	}

	token, err := s.tokens.Issue(user.ID)
	if err != nil {
		return Session{}, err
	}
	return Session{
		Token:      token,
		SaltAuth:   user.SaltAuth,
		SaltData:   user.SaltData,
		KDFVersion: user.KDFVersion,
		Verifier:   user.Verifier,
	}, nil
}

// acquireKDF занимает место в очереди на вывод ключа и возвращает функцию,
// освобождающую его.
func (s *Service) acquireKDF(ctx context.Context) (func(), error) {
	if !s.pending.TryAcquire(1) {
		return nil, ErrBusy
	}
	if err := s.kdf.Acquire(ctx, 1); err != nil {
		s.pending.Release(1)
		return nil, fmt.Errorf("wait for key derivation slot: %w", err)
	}
	return func() {
		s.kdf.Release(1)
		s.pending.Release(1)
	}, nil
}

// Push сохраняет шифротекст поверх версии baseRevision.
func (s *Service) Push(ctx context.Context, userID string, rec model.SecretRecord, baseRevision int64) (int64, error) {
	if len(rec.Payload) > model.MaxSecretSize {
		return 0, ErrPayloadTooLarge
	}
	if rec.ID == "" {
		return 0, ErrInvalidID
	}
	return s.repo.SaveSecret(ctx, userID, rec, baseRevision)
}

// Pull отдаёт изменения пользователя с ревизией больше since.
func (s *Service) Pull(ctx context.Context, userID string, since int64) iter.Seq2[model.SecretRecord, error] {
	return s.repo.EachSecretSince(ctx, userID, since)
}

// Get возвращает одну запись пользователя.
func (s *Service) Get(ctx context.Context, userID, id string) (model.SecretRecord, error) {
	rec, err := s.repo.GetSecret(ctx, userID, id)
	if errors.Is(err, storage.ErrSecretNotFound) {
		return model.SecretRecord{}, ErrNotFound
	}
	if err != nil {
		return model.SecretRecord{}, err
	}
	if rec.Deleted {
		return model.SecretRecord{}, ErrNotFound
	}
	return rec, nil
}
