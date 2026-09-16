package transport

import "fmt"

// Параметры повторов. Повторяется только отказ UNAVAILABLE — сервер недоступен
// или соединение оборвалось, то есть запрос заведомо не был обработан.
const (
	maxRetryAttempts  = 4
	initialBackoff    = "0.2s"
	maxBackoff        = "2s"
	backoffMultiplier = 2
)

// retryableMethods — вызовы, которые безопасно повторять: чтения и вход.
// Push и Upload сюда не входят: повтор после потерянного ответа столкнул бы
// клиента с его же собственной записью как с конфликтом.
var retryableMethods = []struct {
	service string
	method  string
}{
	{"gophkeeper.v1.AuthService", "GetSalts"},
	{"gophkeeper.v1.AuthService", "Login"},
	{"gophkeeper.v1.VaultService", "Pull"},
	{"gophkeeper.v1.VaultService", "Download"},
}

// serviceConfig описывает повторы средствами самого gRPC, поэтому код вызовов
// о них ничего не знает.
func serviceConfig() string {
	names := ""
	for i, m := range retryableMethods {
		if i > 0 {
			names += ", "
		}
		names += fmt.Sprintf(`{"service": %q, "method": %q}`, m.service, m.method)
	}

	return fmt.Sprintf(`{
		"methodConfig": [{
			"name": [%s],
			"retryPolicy": {
				"maxAttempts": %d,
				"initialBackoff": %q,
				"maxBackoff": %q,
				"backoffMultiplier": %d,
				"retryableStatusCodes": ["UNAVAILABLE"]
			}
		}]
	}`, names, maxRetryAttempts, initialBackoff, maxBackoff, backoffMultiplier)
}
