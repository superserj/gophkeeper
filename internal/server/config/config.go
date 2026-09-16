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
const defaultAddress = ":3200"

// Имена настроек. Одно и то же имя служит ключом в JSON-файле и внутренним
// ключом источников, чтобы источники не расходились между собой.
const (
	keyAddress  = "grpc_address"
	keyDatabase = "database_uri"
	keySecret   = "jwt_secret"
	keyCert     = "cert_file"
	keyKey      = "key_file"
)

// Соответствие флагов и переменных окружения именам настроек.
var (
	flagNames = map[string]string{
		"a":    keyAddress,
		"d":    keyDatabase,
		"k":    keySecret,
		"cert": keyCert,
		"key":  keyKey,
	}
	envNames = map[string]string{
		"GRPC_ADDRESS": keyAddress,
		"DATABASE_URI": keyDatabase,
		"JWT_SECRET":   keySecret,
		"TLS_CERT":     keyCert,
		"TLS_KEY":      keyKey,
	}
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

// Parse читает конфигурацию: сначала файл, затем переменные окружения, затем
// флаги — каждый следующий источник перекрывает предыдущий.
//
// Флаги приоритетнее окружения: флаг — это явное намерение того, кто запускает
// процесс сейчас, а переменные приходят из среды (compose, systemd, CI) и должны
// перекрываться без её правки.
//
// Источник считается задавшим настройку по факту её присутствия, а не по
// непустому значению: объявленная пустой переменная и флаг с пустым значением
// означают «значения нет» и должны перекрывать то, что пришло раньше.
func Parse(args []string) (Config, error) {
	fs := flag.NewFlagSet("gophkeeper-server", flag.ContinueOnError)

	fs.String("c", "", "path to JSON config file")
	fs.String("a", "", "gRPC server address")
	fs.String("d", "", "PostgreSQL connection string")
	fs.String("k", "", "secret for signing access tokens")
	fs.String("cert", "", "path to TLS certificate")
	fs.String("key", "", "path to TLS private key")

	if err := fs.Parse(args); err != nil {
		return Config{}, err
	}

	// Путь к файлу подчиняется тому же правилу: явный флаг сильнее переменной,
	// причём пустой -c означает «файла нет» и отключает чтение CONFIG.
	path, ok := configPath(fs)
	if !ok {
		path = os.Getenv("CONFIG")
	}

	cfg := Config{Address: defaultAddress}
	if path != "" {
		fromFile, err := readFile(path)
		if err != nil {
			return Config{}, err
		}
		cfg = fromFile
		if cfg.Address == "" {
			cfg.Address = defaultAddress
		}
	}

	cfg = apply(cfg, environment())
	cfg = apply(cfg, flags(fs))

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

// configPath возвращает значение флага -c и признак того, что флаг задан.
func configPath(fs *flag.FlagSet) (string, bool) {
	var (
		path  string
		given bool
	)
	fs.Visit(func(f *flag.Flag) {
		if f.Name == "c" {
			path, given = f.Value.String(), true
		}
	})
	return path, given
}

// environment собирает объявленные переменные окружения. LookupEnv отличает
// пустое значение от незаданного, поэтому пустая переменная тоже считается
// заданной и перекрывает файл.
func environment() map[string]string {
	values := make(map[string]string, len(envNames))
	for name, key := range envNames {
		if value, ok := os.LookupEnv(name); ok {
			values[key] = value
		}
	}
	return values
}

// flags собирает только те флаги, которые указаны в командной строке: Visit
// обходит заданные, а не все объявленные.
func flags(fs *flag.FlagSet) map[string]string {
	values := make(map[string]string, len(flagNames))
	fs.Visit(func(f *flag.Flag) {
		if key, ok := flagNames[f.Name]; ok {
			values[key] = f.Value.String()
		}
	})
	return values
}

func apply(cfg Config, values map[string]string) Config {
	if value, ok := values[keyAddress]; ok {
		cfg.Address = value
	}
	if value, ok := values[keyDatabase]; ok {
		cfg.DatabaseURI = value
	}
	if value, ok := values[keySecret]; ok {
		cfg.JWTSecret = value
	}
	if value, ok := values[keyCert]; ok {
		cfg.CertFile = value
	}
	if value, ok := values[keyKey]; ok {
		cfg.KeyFile = value
	}
	return cfg
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
