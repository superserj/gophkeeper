BUILD_VERSION ?= $(shell git describe --tags --always 2>/dev/null || echo dev)
BUILD_DATE ?= $(shell date -u +%Y-%m-%dT%H:%M:%SZ)
LDFLAGS = -X main.buildVersion=$(BUILD_VERSION) -X main.buildDate=$(BUILD_DATE)

CLIENT_PLATFORMS = linux/amd64 linux/arm64 darwin/amd64 darwin/arm64 windows/amd64

.PHONY: build
build:
	go build -ldflags "$(LDFLAGS)" -o bin/gophkeeper ./cmd/gophkeeper
	go build -ldflags "$(LDFLAGS)" -o bin/gophkeeper-server ./cmd/gophkeeper-server

# build-all собирает клиент под все поддерживаемые платформы.
.PHONY: build-all
build-all:
	@for platform in $(CLIENT_PLATFORMS); do \
		os=$${platform%/*}; arch=$${platform#*/}; \
		ext=""; if [ "$$os" = "windows" ]; then ext=".exe"; fi; \
		echo "build $$os/$$arch"; \
		GOOS=$$os GOARCH=$$arch go build -ldflags "$(LDFLAGS)" \
			-o bin/gophkeeper-$$os-$$arch$$ext ./cmd/gophkeeper || exit 1; \
	done

.PHONY: test
test:
	go test ./... -count=1

# cover считает покрытие по коду системы: сгенерированный protobuf и main-пакеты
# в знаменатель не входят.
.PHONY: cover
cover:
	go test ./... -count=1 -coverpkg=./internal/... -coverprofile=coverage.out
	go tool cover -func=coverage.out | tail -1

.PHONY: vet
vet:
	go vet ./...

# proto перегенерирует код по контракту.
.PHONY: proto
proto:
	protoc --go_out=. --go_opt=paths=source_relative \
		--go-grpc_out=. --go-grpc_opt=paths=source_relative \
		proto/gophkeeper/v1/gophkeeper.proto

# cert выпускает самоподписанный сертификат для локального запуска.
.PHONY: cert
cert:
	openssl req -x509 -newkey rsa:2048 -nodes -days 365 \
		-subj "/CN=localhost" -addext "subjectAltName=DNS:localhost,IP:127.0.0.1" \
		-keyout server.key -out server.crt

.PHONY: clean
clean:
	rm -rf bin coverage.out
