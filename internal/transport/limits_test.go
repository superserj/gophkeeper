package transport

import (
	"encoding/json"
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
	if len(DialOptions()) != 2 {
		t.Fatalf("получено %d клиентских опций", len(DialOptions()))
	}
}

func TestServiceConfigIsValidJSON(t *testing.T) {
	var config struct {
		MethodConfig []struct {
			Name []struct {
				Service string `json:"service"`
				Method  string `json:"method"`
			} `json:"name"`
			RetryPolicy struct {
				MaxAttempts int `json:"maxAttempts"`
			} `json:"retryPolicy"`
		} `json:"methodConfig"`
	}
	if err := json.Unmarshal([]byte(serviceConfig()), &config); err != nil {
		t.Fatalf("конфигурация повторов не разбирается: %v", err)
	}
	if len(config.MethodConfig) != 1 || config.MethodConfig[0].RetryPolicy.MaxAttempts != maxRetryAttempts {
		t.Fatalf("разобрана конфигурация %+v", config)
	}

	// Push и Upload повторять нельзя: повтор после потерянного ответа столкнул
	// бы клиента с его же записью как с конфликтом.
	for _, name := range config.MethodConfig[0].Name {
		if name.Method == "Push" || name.Method == "Upload" {
			t.Fatalf("метод %s попал в список повторяемых", name.Method)
		}
	}
}
