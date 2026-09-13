// Package model описывает доменные типы GophKeeper.
//
// Полезная нагрузка записи (тип, название, поля, метаинформация) сериализуется
// в JSON и шифруется на клиенте целиком, поэтому сервер работает только с
// SecretRecord и не знает, что лежит внутри.
package model

import (
	"encoding/json"
	"errors"
	"fmt"
	"time"
)

// SecretKind — тип хранимой записи.
type SecretKind string

// Типы записей из технического задания.
const (
	// KindCredentials — пара логин/пароль.
	KindCredentials SecretKind = "credentials"
	// KindText — произвольные текстовые данные.
	KindText SecretKind = "text"
	// KindBinary — произвольные бинарные данные.
	KindBinary SecretKind = "binary"
	// KindCard — данные банковской карты.
	KindCard SecretKind = "card"
)

// MaxSecretSize ограничивает размер одной записи после шифрования.
// Значение согласовано с лимитом gRPC-сообщения, см. пакет transport.
const MaxSecretSize = 10 << 20

// ErrEmptyName возвращается, когда у записи нет названия: без него пользователь
// не найдёт её в списке.
var ErrEmptyName = errors.New("secret name is empty")

// Credentials — пара логин/пароль.
type Credentials struct {
	Login    string `json:"login"`
	Password string `json:"password"`
}

// Card — данные банковской карты.
type Card struct {
	Number  string `json:"number"`
	Holder  string `json:"holder"`
	Expires string `json:"expires"`
	CVV     string `json:"cvv"`
}

// Secret — расшифрованное содержимое записи. Заполнено поле, соответствующее Kind.
type Secret struct {
	Kind        SecretKind   `json:"kind"`
	Name        string       `json:"name"`
	Meta        string       `json:"meta,omitempty"`
	Credentials *Credentials `json:"credentials,omitempty"`
	Text        string       `json:"text,omitempty"`
	Binary      []byte       `json:"binary,omitempty"`
	Card        *Card        `json:"card,omitempty"`
}

// SecretRecord — запись в том виде, в каком её хранит и передаёт сервер:
// шифротекст плюс служебные поля синхронизации.
type SecretRecord struct {
	ID        string
	Payload   []byte
	Deleted   bool
	Revision  int64
	UpdatedAt time.Time
}

// Validate проверяет, что заполнены обязательные поля и поле, соответствующее Kind.
func (s *Secret) Validate() error {
	if s.Name == "" {
		return ErrEmptyName
	}
	switch s.Kind {
	case KindCredentials:
		if s.Credentials == nil || s.Credentials.Login == "" {
			return errors.New("credentials are empty")
		}
	case KindText:
		if s.Text == "" {
			return errors.New("text is empty")
		}
	case KindBinary:
		if len(s.Binary) == 0 {
			return errors.New("binary payload is empty")
		}
	case KindCard:
		if s.Card == nil || s.Card.Number == "" {
			return errors.New("card number is empty")
		}
	default:
		return fmt.Errorf("unknown secret kind %q", s.Kind)
	}
	return nil
}

// Marshal сериализует запись перед шифрованием.
func (s *Secret) Marshal() ([]byte, error) {
	if err := s.Validate(); err != nil {
		return nil, err
	}
	data, err := json.Marshal(s)
	if err != nil {
		return nil, fmt.Errorf("marshal secret: %w", err)
	}
	return data, nil
}

// UnmarshalSecret разбирает расшифрованную полезную нагрузку.
func UnmarshalSecret(data []byte) (*Secret, error) {
	var s Secret
	if err := json.Unmarshal(data, &s); err != nil {
		return nil, fmt.Errorf("unmarshal secret: %w", err)
	}
	return &s, nil
}
