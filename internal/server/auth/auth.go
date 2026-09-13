// Package auth хеширует присланные клиентом ключи аутентификации и выдаёт токены доступа.
//
// Мастер-пароль сервер не видит: клиент присылает authKey, выведенный из пароля
// по Argon2id, а сервер хранит хеш уже от этого значения.
package auth

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"golang.org/x/crypto/argon2"
)

// Параметры хеширования authKey на сервере.
const (
	hashTime    uint32 = 1
	hashMemory  uint32 = 64 * 1024
	hashThreads uint8  = 4
	hashLength  uint32 = 32
	hashSaltLen        = 16
)

// TokenTTL — срок жизни выданного токена.
const TokenTTL = 24 * time.Hour

// Ошибки аутентификации.
var (
	// ErrBadCredentials возвращается, когда ключ не совпал с сохранённым хешем.
	ErrBadCredentials = errors.New("invalid credentials")
	// ErrBadToken возвращается для просроченного или подделанного токена.
	ErrBadToken = errors.New("invalid token")
)

// HashAuthKey считает хеш от ключа аутентификации со случайной солью.
// Возвращает строку вида "argon2id$m$t$p$salt$hash" в base64 без выравнивания.
func HashAuthKey(authKey []byte) (string, error) {
	salt := make([]byte, hashSaltLen)
	if _, err := rand.Read(salt); err != nil {
		return "", fmt.Errorf("generate salt: %w", err)
	}
	hash := argon2.IDKey(authKey, salt, hashTime, hashMemory, hashThreads, hashLength)

	enc := base64.RawStdEncoding
	return strings.Join([]string{
		"argon2id",
		strconv.FormatUint(uint64(hashMemory), 10),
		strconv.FormatUint(uint64(hashTime), 10),
		strconv.FormatUint(uint64(hashThreads), 10),
		enc.EncodeToString(salt),
		enc.EncodeToString(hash),
	}, "$"), nil
}

// VerifyAuthKey сверяет ключ с хешем, созданным HashAuthKey.
func VerifyAuthKey(encoded string, authKey []byte) error {
	parts := strings.Split(encoded, "$")
	if len(parts) != 6 || parts[0] != "argon2id" {
		return ErrBadCredentials
	}

	memory, err := strconv.ParseUint(parts[1], 10, 32)
	if err != nil {
		return ErrBadCredentials
	}
	iterations, err := strconv.ParseUint(parts[2], 10, 32)
	if err != nil {
		return ErrBadCredentials
	}
	threads, err := strconv.ParseUint(parts[3], 10, 8)
	if err != nil {
		return ErrBadCredentials
	}

	enc := base64.RawStdEncoding
	salt, err := enc.DecodeString(parts[4])
	if err != nil {
		return ErrBadCredentials
	}
	want, err := enc.DecodeString(parts[5])
	if err != nil {
		return ErrBadCredentials
	}

	got := argon2.IDKey(authKey, salt, uint32(iterations), uint32(memory), uint8(threads), uint32(len(want)))
	if subtle.ConstantTimeCompare(got, want) != 1 {
		return ErrBadCredentials
	}
	return nil
}

// TokenManager выпускает и проверяет токены доступа.
type TokenManager struct {
	secret []byte
	ttl    time.Duration
}

// NewTokenManager создаёт менеджер токенов с заданным секретом подписи.
func NewTokenManager(secret string, ttl time.Duration) *TokenManager {
	if ttl <= 0 {
		ttl = TokenTTL
	}
	return &TokenManager{secret: []byte(secret), ttl: ttl}
}

// Issue выпускает токен для пользователя.
func (m *TokenManager) Issue(userID int64) (string, error) {
	now := time.Now()
	claims := jwt.RegisteredClaims{
		Subject:   strconv.FormatInt(userID, 10),
		IssuedAt:  jwt.NewNumericDate(now),
		ExpiresAt: jwt.NewNumericDate(now.Add(m.ttl)),
	}
	token, err := jwt.NewWithClaims(jwt.SigningMethodHS256, claims).SignedString(m.secret)
	if err != nil {
		return "", fmt.Errorf("sign token: %w", err)
	}
	return token, nil
}

// Parse проверяет токен и возвращает идентификатор пользователя.
func (m *TokenManager) Parse(token string) (int64, error) {
	var claims jwt.RegisteredClaims
	parsed, err := jwt.ParseWithClaims(token, &claims, func(t *jwt.Token) (any, error) {
		if _, ok := t.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, ErrBadToken
		}
		return m.secret, nil
	})
	if err != nil || !parsed.Valid {
		return 0, ErrBadToken
	}

	userID, err := strconv.ParseInt(claims.Subject, 10, 64)
	if err != nil {
		return 0, ErrBadToken
	}
	return userID, nil
}
