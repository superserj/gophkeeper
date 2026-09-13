// Package crypto выводит ключи из мастер-пароля и шифрует секреты клиента.
//
// Мастер-пароль никогда не покидает клиента. Из него на разных солях выводятся
// два независимых значения: authKey уходит на сервер вместо пароля, dataKey
// шифрует полезную нагрузку и остаётся только в памяти процесса.
package crypto

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"errors"
	"fmt"

	"golang.org/x/crypto/argon2"
)

// KDFVersion — номер схемы вывода ключей. Параметры Argon2id входят в результат,
// поэтому менять их можно только вместе с версией: иначе ранее сохранённые данные
// перестанут расшифровываться.
const KDFVersion uint32 = 1

// Параметры Argon2id для authKey и dataKey. Разные соли и разное число проходов
// делают значения независимыми: знание одного не помогает восстановить другое.
const (
	authTime    uint32 = 1
	authMemory  uint32 = 64 * 1024
	authThreads uint8  = 4

	dataTime    uint32 = 3
	dataMemory  uint32 = 64 * 1024
	dataThreads uint8  = 4
)

// Размеры в байтах.
const (
	// SaltSize — длина соли, которую клиент генерирует при регистрации.
	SaltSize = 32
	// KeySize — длина выводимых ключей, AES-256.
	KeySize = 32
	// NonceSize — длина nonce AES-GCM.
	NonceSize = 12
)

// verifierPlaintext шифруется на dataKey при регистрации и хранится рядом с солями.
// Успешная расшифровка подтверждает, что пользователь ввёл тот же мастер-пароль.
const verifierPlaintext = "gophkeeper-verifier-v1"

// ErrWrongPassword возвращается, когда данные не расшифровываются выведенным ключом.
var ErrWrongPassword = errors.New("wrong master password")

// NewSalt возвращает случайную соль длиной SaltSize.
func NewSalt() ([]byte, error) {
	salt := make([]byte, SaltSize)
	if _, err := rand.Read(salt); err != nil {
		return nil, fmt.Errorf("generate salt: %w", err)
	}
	return salt, nil
}

// DeriveAuthKey выводит из мастер-пароля значение, которое клиент отправляет
// серверу вместо пароля.
func DeriveAuthKey(master string, salt []byte) []byte {
	return argon2.IDKey([]byte(master), salt, authTime, authMemory, authThreads, KeySize)
}

// DeriveDataKey выводит из мастер-пароля ключ шифрования секретов.
func DeriveDataKey(master string, salt []byte) []byte {
	return argon2.IDKey([]byte(master), salt, dataTime, dataMemory, dataThreads, KeySize)
}

// Seal шифрует plaintext ключом key в режиме AES-256-GCM и возвращает nonce||ciphertext.
//
// Nonce каждый раз новый и случайный: клиенты одного владельца шифруют одним ключом
// независимо друг от друга, и повтор nonce раскрыл бы связь между открытыми текстами.
func Seal(key, aad, plaintext []byte) ([]byte, error) {
	gcm, err := newGCM(key)
	if err != nil {
		return nil, err
	}
	nonce := make([]byte, NonceSize)
	if _, err := rand.Read(nonce); err != nil {
		return nil, fmt.Errorf("generate nonce: %w", err)
	}
	return gcm.Seal(nonce, nonce, plaintext, aad), nil
}

// Open расшифровывает результат Seal. Если данные не проходят проверку
// аутентичности, возвращается ErrWrongPassword.
func Open(key, aad, blob []byte) ([]byte, error) {
	gcm, err := newGCM(key)
	if err != nil {
		return nil, err
	}
	if len(blob) < NonceSize {
		return nil, ErrWrongPassword
	}
	plaintext, err := gcm.Open(nil, blob[:NonceSize], blob[NonceSize:], aad)
	if err != nil {
		return nil, ErrWrongPassword
	}
	return plaintext, nil
}

// NewVerifier шифрует контрольную строку на dataKey. Значение хранится и на сервере,
// и в локальном профиле, чтобы опечатка в мастер-пароле обнаруживалась до записи
// данных, а не через сутки при попытке их прочитать.
func NewVerifier(dataKey []byte, login string) ([]byte, error) {
	return Seal(dataKey, []byte(login), []byte(verifierPlaintext))
}

// CheckVerifier проверяет мастер-пароль по значению, созданному NewVerifier.
func CheckVerifier(dataKey []byte, login string, verifier []byte) error {
	plaintext, err := Open(dataKey, []byte(login), verifier)
	if err != nil {
		return err
	}
	if string(plaintext) != verifierPlaintext {
		return ErrWrongPassword
	}
	return nil
}

func newGCM(key []byte) (cipher.AEAD, error) {
	if len(key) != KeySize {
		return nil, fmt.Errorf("key must be %d bytes, got %d", KeySize, len(key))
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("new cipher: %w", err)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("new gcm: %w", err)
	}
	return gcm, nil
}
