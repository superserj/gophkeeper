package model

import (
	"bytes"
	"errors"
	"testing"
)

func TestValidate(t *testing.T) {
	tests := []struct {
		name    string
		secret  Secret
		wantErr bool
	}{
		{
			name:   "credentials",
			secret: Secret{Kind: KindCredentials, Name: "bank", Credentials: &Credentials{Login: "user", Password: "pass"}},
		},
		{
			name:   "text",
			secret: Secret{Kind: KindText, Name: "note", Text: "секрет"},
		},
		{
			name:   "binary",
			secret: Secret{Kind: KindBinary, Name: "scan", Binary: []byte{1, 2, 3}},
		},
		{
			name:   "card",
			secret: Secret{Kind: KindCard, Name: "visa", Card: &Card{Number: "4111111111111111"}},
		},
		{
			name:    "no name",
			secret:  Secret{Kind: KindText, Text: "секрет"},
			wantErr: true,
		},
		{
			name:    "empty credentials",
			secret:  Secret{Kind: KindCredentials, Name: "bank"},
			wantErr: true,
		},
		{
			name:    "empty text",
			secret:  Secret{Kind: KindText, Name: "note"},
			wantErr: true,
		},
		{
			name:    "empty binary",
			secret:  Secret{Kind: KindBinary, Name: "scan"},
			wantErr: true,
		},
		{
			name:    "card without number",
			secret:  Secret{Kind: KindCard, Name: "visa", Card: &Card{}},
			wantErr: true,
		},
		{
			name:    "text in another encoding",
			secret:  Secret{Kind: KindText, Name: "note", Text: string([]byte{0xcf, 0xf0, 0xe8, 0xe2, 0xe5, 0xf2})},
			wantErr: true,
		},
		{
			name:    "unknown kind",
			secret:  Secret{Kind: "otp", Name: "token"},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.secret.Validate()
			if tt.wantErr && err == nil {
				t.Fatal("ожидалась ошибка валидации")
			}
			if !tt.wantErr && err != nil {
				t.Fatalf("неожиданная ошибка: %v", err)
			}
		})
	}
}

func TestValidateReportsEmptyName(t *testing.T) {
	secret := Secret{Kind: KindText, Text: "секрет"}
	if err := secret.Validate(); !errors.Is(err, ErrEmptyName) {
		t.Fatalf("получено %v, ожидалась ErrEmptyName", err)
	}
}

func TestValidateRejectsBrokenEncoding(t *testing.T) {
	// «Привет» в Windows-1251: JSON заменил бы эти байты символом замены,
	// и восстановить исходный текст стало бы нельзя.
	secret := Secret{Kind: KindText, Name: "note", Text: string([]byte{0xcf, 0xf0, 0xe8, 0xe2, 0xe5, 0xf2})}
	if err := secret.Validate(); !errors.Is(err, ErrNotUTF8) {
		t.Fatalf("получено %v, ожидалась ErrNotUTF8", err)
	}
}

func TestMarshalRoundTrip(t *testing.T) {
	secret := Secret{
		Kind:   KindBinary,
		Name:   "архив",
		Meta:   "паспорт",
		Binary: []byte{0, 1, 2, 3, 255},
	}

	data, err := secret.Marshal()
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}

	got, err := UnmarshalSecret(data)
	if err != nil {
		t.Fatalf("UnmarshalSecret: %v", err)
	}
	if got.Name != secret.Name || got.Meta != secret.Meta || !bytes.Equal(got.Binary, secret.Binary) {
		t.Fatalf("после round-trip получено %+v", got)
	}
}

func TestMarshalRejectsInvalidSecret(t *testing.T) {
	secret := Secret{Kind: KindText, Name: "note"}
	if _, err := secret.Marshal(); err == nil {
		t.Fatal("Marshal принял запись без содержимого")
	}
}

func TestUnmarshalRejectsGarbage(t *testing.T) {
	if _, err := UnmarshalSecret([]byte("не json")); err == nil {
		t.Fatal("UnmarshalSecret принял мусор")
	}
}
