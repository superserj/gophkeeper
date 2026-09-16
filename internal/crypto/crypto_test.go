package crypto

import (
	"bytes"
	"testing"
)

func TestDeriveKeysDeterministic(t *testing.T) {
	salt := bytes.Repeat([]byte{1}, SaltSize)

	first := DeriveDataKey("master", salt)
	second := DeriveDataKey("master", salt)
	if !bytes.Equal(first, second) {
		t.Fatal("dataKey не воспроизводится на тех же входных данных")
	}
	if len(first) != KeySize {
		t.Fatalf("длина ключа %d, ожидалась %d", len(first), KeySize)
	}
}

func TestDeriveKeysDifferOnSaltAndPassword(t *testing.T) {
	saltA := bytes.Repeat([]byte{1}, SaltSize)
	saltB := bytes.Repeat([]byte{2}, SaltSize)

	if bytes.Equal(DeriveDataKey("master", saltA), DeriveDataKey("master", saltB)) {
		t.Error("разные соли дали одинаковый ключ")
	}
	if bytes.Equal(DeriveDataKey("master", saltA), DeriveDataKey("other", saltA)) {
		t.Error("разные пароли дали одинаковый ключ")
	}
	if bytes.Equal(DeriveAuthKey("master", saltA), DeriveDataKey("master", saltA)) {
		t.Error("authKey совпал с dataKey")
	}
}

func TestSealOpenRoundTrip(t *testing.T) {
	key := DeriveDataKey("master", bytes.Repeat([]byte{3}, SaltSize))
	plaintext := []byte("логин и пароль от банка")

	blob, err := Seal(key, []byte("secret-id"), plaintext)
	if err != nil {
		t.Fatalf("Seal: %v", err)
	}

	got, err := Open(key, []byte("secret-id"), blob)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	if !bytes.Equal(got, plaintext) {
		t.Fatalf("расшифровано %q, ожидалось %q", got, plaintext)
	}
}

func TestSealUsesFreshNonce(t *testing.T) {
	key := DeriveDataKey("master", bytes.Repeat([]byte{4}, SaltSize))

	first, err := Seal(key, nil, []byte("одно и то же"))
	if err != nil {
		t.Fatalf("Seal: %v", err)
	}
	second, err := Seal(key, nil, []byte("одно и то же"))
	if err != nil {
		t.Fatalf("Seal: %v", err)
	}
	if bytes.Equal(first[:NonceSize], second[:NonceSize]) {
		t.Fatal("nonce повторился между вызовами")
	}
	if bytes.Equal(first, second) {
		t.Fatal("шифротекст повторился между вызовами")
	}
}

func TestOpenRejectsForeignAAD(t *testing.T) {
	key := DeriveDataKey("master", bytes.Repeat([]byte{5}, SaltSize))

	blob, err := Seal(key, []byte("secret-a"), []byte("данные"))
	if err != nil {
		t.Fatalf("Seal: %v", err)
	}
	if _, err := Open(key, []byte("secret-b"), blob); err != ErrWrongPassword {
		t.Fatalf("подмена идентификатора записи дала %v, ожидалась ErrWrongPassword", err)
	}
}

func TestOpenRejectsWrongKeyAndShortBlob(t *testing.T) {
	salt := bytes.Repeat([]byte{6}, SaltSize)
	blob, err := Seal(DeriveDataKey("master", salt), nil, []byte("данные"))
	if err != nil {
		t.Fatalf("Seal: %v", err)
	}

	if _, err := Open(DeriveDataKey("other", salt), nil, blob); err != ErrWrongPassword {
		t.Fatalf("чужой ключ дал %v, ожидалась ErrWrongPassword", err)
	}
	if _, err := Open(DeriveDataKey("master", salt), nil, blob[:NonceSize-1]); err != ErrWrongPassword {
		t.Fatalf("обрезанный блоб дал %v, ожидалась ErrWrongPassword", err)
	}
}

func TestVerifier(t *testing.T) {
	salt := bytes.Repeat([]byte{7}, SaltSize)
	key := DeriveDataKey("master", salt)

	verifier, err := NewVerifier(key, "user")
	if err != nil {
		t.Fatalf("NewVerifier: %v", err)
	}
	if err := CheckVerifier(key, "user", verifier); err != nil {
		t.Fatalf("верификатор не принял правильный пароль: %v", err)
	}
	if err := CheckVerifier(DeriveDataKey("typo", salt), "user", verifier); err != ErrWrongPassword {
		t.Fatalf("опечатка в пароле дала %v, ожидалась ErrWrongPassword", err)
	}
	if err := CheckVerifier(key, "other", verifier); err != ErrWrongPassword {
		t.Fatalf("чужой логин дал %v, ожидалась ErrWrongPassword", err)
	}
}

func TestNewSaltIsRandom(t *testing.T) {
	first, err := NewSalt()
	if err != nil {
		t.Fatalf("NewSalt: %v", err)
	}
	second, err := NewSalt()
	if err != nil {
		t.Fatalf("NewSalt: %v", err)
	}
	if len(first) != SaltSize {
		t.Fatalf("длина соли %d, ожидалась %d", len(first), SaltSize)
	}
	if bytes.Equal(first, second) {
		t.Fatal("две соли подряд совпали")
	}
}

func TestSealRejectsBadKeyLength(t *testing.T) {
	if _, err := Seal([]byte("короткий ключ"), nil, []byte("данные")); err == nil {
		t.Fatal("Seal принял ключ неверной длины")
	}
}
