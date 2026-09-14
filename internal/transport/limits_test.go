package transport

import (
	"testing"

	"github.com/superserj/gophkeeper/internal/model"
)

func TestMessageSizeCoversLargestSecret(t *testing.T) {
	if MaxMessageSize <= model.MaxSecretSize {
		t.Fatalf("лимит сообщения %d не вмещает запись размером %d", MaxMessageSize, model.MaxSecretSize)
	}
}

func TestOptionsAreSet(t *testing.T) {
	if len(ServerOptions()) != 2 {
		t.Fatalf("получено %d серверных опций", len(ServerOptions()))
	}
	if len(DialOptions()) != 1 {
		t.Fatalf("получено %d клиентских опций", len(DialOptions()))
	}
}
