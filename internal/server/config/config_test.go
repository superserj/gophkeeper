package config

import (
	"errors"
	"os"
	"path/filepath"
	"testing"
)

func TestParseFlags(t *testing.T) {
	cfg, err := Parse([]string{
		"-a", ":4000",
		"-d", "postgres://localhost/keeper",
		"-k", "secret",
		"-cert", "cert.pem",
		"-key", "key.pem",
	})
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if cfg.Address != ":4000" || cfg.DatabaseURI != "postgres://localhost/keeper" {
		t.Fatalf("получена конфигурация %+v", cfg)
	}
}

func TestParseUsesDefaultAddress(t *testing.T) {
	cfg, err := Parse([]string{"-d", "postgres://localhost/keeper", "-k", "secret", "-cert", "c", "-key", "k"})
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if cfg.Address != defaultAddress {
		t.Fatalf("адрес %q, ожидался %q", cfg.Address, defaultAddress)
	}
}

func TestFlagsOverrideEnv(t *testing.T) {
	t.Setenv("GRPC_ADDRESS", ":5000")
	t.Setenv("DATABASE_URI", "postgres://env/keeper")
	t.Setenv("JWT_SECRET", "env-secret")
	t.Setenv("TLS_CERT", "env-cert.pem")
	t.Setenv("TLS_KEY", "env-key.pem")

	cfg, err := Parse([]string{"-a", ":4000", "-d", "postgres://flag/keeper", "-k", "flag-secret"})
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if cfg.Address != ":4000" || cfg.DatabaseURI != "postgres://flag/keeper" || cfg.JWTSecret != "flag-secret" {
		t.Fatalf("флаги не перекрыли окружение: %+v", cfg)
	}
	// То, что флагом не задано, берётся из окружения.
	if cfg.CertFile != "env-cert.pem" || cfg.KeyFile != "env-key.pem" {
		t.Fatalf("значения из окружения потеряны: %+v", cfg)
	}
}

func TestEnvOverridesFile(t *testing.T) {
	path := writeConfig(t, `{
		"grpc_address": ":7000",
		"database_uri": "postgres://file/keeper",
		"jwt_secret": "file-secret",
		"cert_file": "file-cert.pem",
		"key_file": "file-key.pem"
	}`)
	t.Setenv("DATABASE_URI", "postgres://env/keeper")

	cfg, err := Parse([]string{"-c", path})
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if cfg.DatabaseURI != "postgres://env/keeper" {
		t.Fatalf("окружение не перекрыло файл: %+v", cfg)
	}
	if cfg.Address != ":7000" {
		t.Fatalf("значение из файла потеряно: %+v", cfg)
	}
}

func TestFlagsOverrideFile(t *testing.T) {
	path := writeConfig(t, `{
		"grpc_address": ":7000",
		"database_uri": "postgres://file/keeper",
		"jwt_secret": "file-secret",
		"cert_file": "file-cert.pem",
		"key_file": "file-key.pem"
	}`)

	cfg, err := Parse([]string{"-c", path, "-a", ":4000"})
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if cfg.Address != ":4000" {
		t.Fatalf("флаг не перекрыл файл: %q", cfg.Address)
	}
	if cfg.DatabaseURI != "postgres://file/keeper" || cfg.JWTSecret != "file-secret" {
		t.Fatalf("значения из файла потеряны: %+v", cfg)
	}
}

func TestConfigPathFromEnv(t *testing.T) {
	path := writeConfig(t, `{
		"database_uri": "postgres://file/keeper",
		"jwt_secret": "file-secret",
		"cert_file": "cert.pem",
		"key_file": "key.pem"
	}`)
	t.Setenv("CONFIG", path)

	cfg, err := Parse(nil)
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if cfg.DatabaseURI != "postgres://file/keeper" {
		t.Fatalf("конфигурация из CONFIG не прочитана: %+v", cfg)
	}
}

func TestConfigFlagOverridesConfigEnv(t *testing.T) {
	fromEnv := writeConfig(t, `{
		"database_uri": "postgres://env-file/keeper",
		"jwt_secret": "env-file-secret",
		"cert_file": "cert.pem",
		"key_file": "key.pem"
	}`)
	fromFlag := writeConfig(t, `{
		"database_uri": "postgres://flag-file/keeper",
		"jwt_secret": "flag-file-secret",
		"cert_file": "cert.pem",
		"key_file": "key.pem"
	}`)
	t.Setenv("CONFIG", fromEnv)

	cfg, err := Parse([]string{"-c", fromFlag})
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if cfg.DatabaseURI != "postgres://flag-file/keeper" {
		t.Fatalf("прочитан файл из окружения, а не из флага: %+v", cfg)
	}
}

func TestValidationErrors(t *testing.T) {
	tests := []struct {
		name string
		args []string
		want error
	}{
		{
			name: "no database",
			args: []string{"-k", "secret", "-cert", "c", "-key", "k"},
			want: ErrNoDatabase,
		},
		{
			name: "no jwt secret",
			args: []string{"-d", "postgres://localhost/keeper", "-cert", "c", "-key", "k"},
			want: ErrNoJWTSecret,
		},
		{
			name: "no tls",
			args: []string{"-d", "postgres://localhost/keeper", "-k", "secret"},
			want: ErrNoTLS,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if _, err := Parse(tt.args); !errors.Is(err, tt.want) {
				t.Fatalf("получено %v, ожидалась %v", err, tt.want)
			}
		})
	}
}

func TestParseReportsBrokenFile(t *testing.T) {
	path := writeConfig(t, "{не json}")
	if _, err := Parse([]string{"-c", path}); err == nil {
		t.Fatal("сломанный файл конфигурации принят")
	}
	if _, err := Parse([]string{"-c", filepath.Join(t.TempDir(), "absent.json")}); err == nil {
		t.Fatal("отсутствующий файл конфигурации принят")
	}
}

func writeConfig(t *testing.T, content string) string {
	t.Helper()

	path := filepath.Join(t.TempDir(), "config.json")
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatalf("write config: %v", err)
	}
	return path
}
