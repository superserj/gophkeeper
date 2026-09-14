package auth

import (
	"errors"
	"strings"
	"testing"
	"time"
)

func TestHashAndVerify(t *testing.T) {
	key := []byte("auth-key")

	encoded, err := HashAuthKey(key)
	if err != nil {
		t.Fatalf("HashAuthKey: %v", err)
	}
	if err := VerifyAuthKey(encoded, key); err != nil {
		t.Fatalf("правильный ключ не прошёл проверку: %v", err)
	}
	if err := VerifyAuthKey(encoded, []byte("other")); !errors.Is(err, ErrBadCredentials) {
		t.Fatalf("чужой ключ дал %v, ожидалась ErrBadCredentials", err)
	}
}

func TestHashUsesRandomSalt(t *testing.T) {
	first, err := HashAuthKey([]byte("auth-key"))
	if err != nil {
		t.Fatalf("HashAuthKey: %v", err)
	}
	second, err := HashAuthKey([]byte("auth-key"))
	if err != nil {
		t.Fatalf("HashAuthKey: %v", err)
	}
	if first == second {
		t.Fatal("два хеша одного ключа совпали — соль не случайная")
	}
}

func TestVerifyRejectsBrokenHash(t *testing.T) {
	valid, err := HashAuthKey([]byte("auth-key"))
	if err != nil {
		t.Fatalf("HashAuthKey: %v", err)
	}
	parts := strings.Split(valid, "$")

	broken := []string{
		"",
		"plain$hash",
		strings.Join([]string{"argon2id", "x", parts[2], parts[3], parts[4], parts[5]}, "$"),
		strings.Join([]string{"argon2id", parts[1], "x", parts[3], parts[4], parts[5]}, "$"),
		strings.Join([]string{"argon2id", parts[1], parts[2], "x", parts[4], parts[5]}, "$"),
		strings.Join([]string{"argon2id", parts[1], parts[2], parts[3], "!!", parts[5]}, "$"),
		strings.Join([]string{"argon2id", parts[1], parts[2], parts[3], parts[4], "!!"}, "$"),
	}
	for _, encoded := range broken {
		if err := VerifyAuthKey(encoded, []byte("auth-key")); !errors.Is(err, ErrBadCredentials) {
			t.Fatalf("хеш %q дал %v, ожидалась ErrBadCredentials", encoded, err)
		}
	}
}

func TestTokenRoundTrip(t *testing.T) {
	manager := NewTokenManager("secret", TokenTTL)

	token, err := manager.Issue(42)
	if err != nil {
		t.Fatalf("Issue: %v", err)
	}
	userID, err := manager.Parse(token)
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if userID != 42 {
		t.Fatalf("получен пользователь %d, ожидался 42", userID)
	}
}

func TestParseRejectsForeignSecret(t *testing.T) {
	token, err := NewTokenManager("secret", TokenTTL).Issue(1)
	if err != nil {
		t.Fatalf("Issue: %v", err)
	}
	if _, err := NewTokenManager("another", TokenTTL).Parse(token); !errors.Is(err, ErrBadToken) {
		t.Fatalf("чужая подпись дала %v, ожидалась ErrBadToken", err)
	}
}

func TestParseRejectsExpiredToken(t *testing.T) {
	manager := NewTokenManager("secret", time.Nanosecond)

	token, err := manager.Issue(1)
	if err != nil {
		t.Fatalf("Issue: %v", err)
	}
	time.Sleep(2 * time.Millisecond)

	if _, err := manager.Parse(token); !errors.Is(err, ErrBadToken) {
		t.Fatalf("просроченный токен дал %v, ожидалась ErrBadToken", err)
	}
}

func TestParseRejectsGarbage(t *testing.T) {
	if _, err := NewTokenManager("secret", TokenTTL).Parse("не токен"); !errors.Is(err, ErrBadToken) {
		t.Fatalf("мусор дал %v, ожидалась ErrBadToken", err)
	}
}

func TestNewTokenManagerFallsBackToDefaultTTL(t *testing.T) {
	manager := NewTokenManager("secret", 0)
	if manager.ttl != TokenTTL {
		t.Fatalf("получен срок %v, ожидался %v", manager.ttl, TokenTTL)
	}
}
