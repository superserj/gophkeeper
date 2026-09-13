// Package service содержит бизнес-логику сервера: регистрацию, вход и работу с записями.
package service

import (
	"context"
	"errors"
	"fmt"

	"github.com/superserj/gophkeeper/internal/crypto"
	"github.com/superserj/gophkeeper/internal/model"
	"github.com/superserj/gophkeeper/internal/server/auth"
	"github.com/superserj/gophkeeper/internal/server/storage"
)

// Repository — доступ к хранилищу, нужный сервису.
type Repository interface {
	CreateUser(ctx context.Context, u storage.User) (int64, error)
	GetUserByLogin(ctx context.Context, login string) (storage.User, error)
	GetSecret(ctx context.Context, userID int64, id string) (model.SecretRecord, error)
	EachSecretSince(ctx context.Context, userID, since int64, fn func(model.SecretRecord) error) error
	SaveSecret(ctx context.Context, userID int64, rec model.SecretRecord, baseRevision int64) (int64, error)
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
	repo   Repository
	tokens *auth.TokenManager
}

// New создаёт сервис.
func New(repo Repository, tokens *auth.TokenManager) *Service {
	return &Service{repo: repo, tokens: tokens}
}

// Register заводит пользователя и сразу выдаёт токен.
func (s *Service) Register(ctx context.Context, c Credentials) (Session, error) {
	if c.Login == "" {
		return Session{}, ErrEmptyLogin
	}
	if len(c.AuthKey) == 0 || len(c.SaltAuth) != crypto.SaltSize || len(c.SaltData) != crypto.SaltSize {
		return Session{}, ErrBadCredentials
	}
	if len(c.Verifier) == 0 {
		return Session{}, ErrBadCredentials
	}

	hash, err := auth.HashAuthKey(c.AuthKey)
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
	user, err := s.repo.GetUserByLogin(ctx, login)
	if errors.Is(err, storage.ErrUserNotFound) {
		return Session{}, ErrBadCredentials
	}
	if err != nil {
		return Session{}, err
	}

	if err := auth.VerifyAuthKey(user.PasswordHash, authKey); err != nil {
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

// Push сохраняет шифротекст поверх версии baseRevision.
func (s *Service) Push(ctx context.Context, userID int64, rec model.SecretRecord, baseRevision int64) (int64, error) {
	if len(rec.Payload) > model.MaxSecretSize {
		return 0, ErrPayloadTooLarge
	}
	if rec.ID == "" {
		return 0, ErrNotFound
	}
	return s.repo.SaveSecret(ctx, userID, rec, baseRevision)
}

// Pull передаёт в fn изменения пользователя с ревизией больше since.
func (s *Service) Pull(ctx context.Context, userID, since int64, fn func(model.SecretRecord) error) error {
	return s.repo.EachSecretSince(ctx, userID, since, fn)
}

// Get возвращает одну запись пользователя.
func (s *Service) Get(ctx context.Context, userID int64, id string) (model.SecretRecord, error) {
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
