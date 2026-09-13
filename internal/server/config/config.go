// Package config собирает настройки сервера из файла, флагов и окружения.
package config

import (
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"os"
)

// Значения по умолчанию.
const (
	defaultAddress = ":3200"
)

// Config — настройки сервера.
type Config struct {
	// Address — адрес, на котором сервер слушает gRPC.
	Address string `json:"grpc_address"`
	// DatabaseURI — строка подключения к PostgreSQL.
	DatabaseURI string `json:"database_uri"`
	// JWTSecret — секрет подписи токенов доступа.
	JWTSecret string `json:"jwt_secret"`
	// CertFile — путь к TLS-сертификату.
	CertFile string `json:"cert_file"`
	// KeyFile — путь к приватному ключу TLS.
	KeyFile string `json:"key_file"`
}

// ErrNoDatabase возвращается, когда не задана строка подключения к базе.
var ErrNoDatabase = errors.New("database uri is not set")

// ErrNoTLS возвращается, когда не задана пара сертификат/ключ: сервер принимает
// шифротексты и токены, поэтому открытое соединение не разрешено.
var ErrNoTLS = errors.New("tls certificate and key are not set")

// ErrNoJWTSecret возвращается, когда не задан секрет подписи токенов.
var ErrNoJWTSecret = errors.New("jwt secret is not set")

// Parse читает конфигурацию: сначала файл, затем флаги, затем переменные
// окружения — каждый следующий источник перекрывает предыдущий.
func Parse(args []string) (Config, error) {
	fs := flag.NewFlagSet("gophkeeper-server", flag.ContinueOnError)

	var (
		configPath  = fs.String("c", "", "path to JSON config file")
		address     = fs.String("a", "", "gRPC server address")
		databaseURI = fs.String("d", "", "PostgreSQL connection string")
		jwtSecret   = fs.String("k", "", "secret for signing access tokens")
		certFile    = fs.String("cert", "", "path to TLS certificate")
		keyFile     = fs.String("key", "", "path to TLS private key")
	)
	if err := fs.Parse(args); err != nil {
		return Config{}, err
	}

	path := *configPath
	if env := os.Getenv("CONFIG"); env != "" {
		path = env
	}

	cfg := Config{Address: defaultAddress}
	if path != "" {
		fromFile, err := readFile(path)
		if err != nil {
			return Config{}, err
		}
		cfg = merge(cfg, fromFile)
	}

	cfg = merge(cfg, Config{
		Address:     *address,
		DatabaseURI: *databaseURI,
		JWTSecret:   *jwtSecret,
		CertFile:    *certFile,
		KeyFile:     *keyFile,
	})

	cfg = merge(cfg, Config{
		Address:     os.Getenv("GRPC_ADDRESS"),
		DatabaseURI: os.Getenv("DATABASE_URI"),
		JWTSecret:   os.Getenv("JWT_SECRET"),
		CertFile:    os.Getenv("TLS_CERT"),
		KeyFile:     os.Getenv("TLS_KEY"),
	})

	return cfg, cfg.validate()
}

func (c Config) validate() error {
	if c.DatabaseURI == "" {
		return ErrNoDatabase
	}
	if c.JWTSecret == "" {
		return ErrNoJWTSecret
	}
	if c.CertFile == "" || c.KeyFile == "" {
		return ErrNoTLS
	}
	return nil
}

func readFile(path string) (Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return Config{}, fmt.Errorf("read config file: %w", err)
	}
	var cfg Config
	if err := json.Unmarshal(data, &cfg); err != nil {
		return Config{}, fmt.Errorf("parse config file: %w", err)
	}
	return cfg, nil
}

// merge накладывает непустые поля next поверх base.
func merge(base, next Config) Config {
	if next.Address != "" {
		base.Address = next.Address
	}
	if next.DatabaseURI != "" {
		base.DatabaseURI = next.DatabaseURI
	}
	if next.JWTSecret != "" {
		base.JWTSecret = next.JWTSecret
	}
	if next.CertFile != "" {
		base.CertFile = next.CertFile
	}
	if next.KeyFile != "" {
		base.KeyFile = next.KeyFile
	}
	return base
}
