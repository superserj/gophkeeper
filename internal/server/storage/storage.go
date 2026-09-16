// Package storage хранит пользователей и шифротексты их записей в PostgreSQL.
package storage

import (
	"context"
	"database/sql"
	"embed"
	"errors"
	"fmt"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
	_ "github.com/jackc/pgx/v5/stdlib"
	"github.com/pressly/goose/v3"

	"github.com/superserj/gophkeeper/internal/model"
)

//go:embed migrations/*.sql
var migrationsFS embed.FS

// Ошибки хранилища, на которые реагирует бизнес-логика.
var (
	// ErrLoginTaken возвращается при регистрации занятого логина.
	ErrLoginTaken = errors.New("login already taken")
	// ErrUserNotFound возвращается, когда пользователя с таким логином нет.
	ErrUserNotFound = errors.New("user not found")
	// ErrSecretNotFound возвращается, когда записи с таким идентификатором нет.
	ErrSecretNotFound = errors.New("secret not found")
)

const uniqueViolation = "23505"

// Ограничения страницы изменений. Одна запись может весить до model.MaxSecretSize,
// поэтому кроме числа записей страница ограничена и суммарным объёмом: иначе сотня
// больших записей заняла бы гигабайт памяти ещё до отправки первого сообщения.
const (
	pullPageSize  = 100
	pullPageBytes = 8 << 20
)

// User — профиль пользователя. Пароль и ключ шифрования сервер не хранит:
// password_hash считается от authKey, а verifier расшифровывается только клиентом.
type User struct {
	ID           int64
	Login        string
	PasswordHash string
	SaltAuth     []byte
	SaltData     []byte
	KDFVersion   uint32
	Verifier     []byte
}

// Storage — пул соединений с PostgreSQL.
type Storage struct {
	pool *pgxpool.Pool
}

// New открывает пул по DSN и применяет миграции.
func New(ctx context.Context, dsn string) (*Storage, error) {
	if err := migrate(dsn); err != nil {
		return nil, err
	}
	pool, err := pgxpool.New(ctx, dsn)
	if err != nil {
		return nil, fmt.Errorf("connect to database: %w", err)
	}
	if err := pool.Ping(ctx); err != nil {
		pool.Close()
		return nil, fmt.Errorf("ping database: %w", err)
	}
	return &Storage{pool: pool}, nil
}

// Close закрывает пул соединений.
func (s *Storage) Close() {
	s.pool.Close()
}

// CreateUser заводит пользователя и возвращает его идентификатор.
func (s *Storage) CreateUser(ctx context.Context, u User) (int64, error) {
	const query = `INSERT INTO users (login, password_hash, salt_auth, salt_data, kdf_version, verifier)
		VALUES ($1, $2, $3, $4, $5, $6) RETURNING id`

	var id int64
	err := s.pool.QueryRow(ctx, query,
		u.Login, u.PasswordHash, u.SaltAuth, u.SaltData, u.KDFVersion, u.Verifier).Scan(&id)
	if err != nil {
		var pgErr *pgconn.PgError
		if errors.As(err, &pgErr) && pgErr.Code == uniqueViolation {
			return 0, ErrLoginTaken
		}
		return 0, fmt.Errorf("insert user: %w", err)
	}
	return id, nil
}

// GetUserByLogin возвращает профиль пользователя.
func (s *Storage) GetUserByLogin(ctx context.Context, login string) (User, error) {
	const query = `SELECT id, login, password_hash, salt_auth, salt_data, kdf_version, verifier
		FROM users WHERE login = $1`

	var u User
	err := s.pool.QueryRow(ctx, query, login).Scan(
		&u.ID, &u.Login, &u.PasswordHash, &u.SaltAuth, &u.SaltData, &u.KDFVersion, &u.Verifier)
	if errors.Is(err, pgx.ErrNoRows) {
		return User{}, ErrUserNotFound
	}
	if err != nil {
		return User{}, fmt.Errorf("select user: %w", err)
	}
	return u, nil
}

// GetSecret возвращает одну запись пользователя.
func (s *Storage) GetSecret(ctx context.Context, userID int64, id string) (model.SecretRecord, error) {
	const query = `SELECT id, payload, deleted, revision, updated_at
		FROM secrets WHERE user_id = $1 AND id = $2`

	var rec model.SecretRecord
	err := s.pool.QueryRow(ctx, query, userID, id).Scan(
		&rec.ID, &rec.Payload, &rec.Deleted, &rec.Revision, &rec.UpdatedAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return model.SecretRecord{}, ErrSecretNotFound
	}
	if err != nil {
		return model.SecretRecord{}, fmt.Errorf("select secret: %w", err)
	}
	return rec, nil
}

// EachSecretSince передаёт в fn все изменения пользователя с ревизией больше since
// строго по возрастанию ревизии: клиент сохраняет курсор вместе с каждым изменением,
// поэтому обрыв связи не должен приводить к пропуску более старой записи.
//
// Изменения читаются страницами, и соединение возвращается в пул до вызова fn:
// иначе клиент, перестающий читать поток, держал бы соединение всё это время и
// несколько таких клиентов исчерпали бы пул.
func (s *Storage) EachSecretSince(ctx context.Context, userID, since int64, fn func(model.SecretRecord) error) error {
	for {
		page, err := s.secretsPage(ctx, userID, since)
		if err != nil {
			return err
		}

		if len(page) == 0 {
			return nil
		}

		for _, rec := range page {
			if err := fn(rec); err != nil {
				return err
			}
			since = rec.Revision
		}
	}
}

// secretsPage читает очередную страницу изменений и закрывает запрос до возврата.
func (s *Storage) secretsPage(ctx context.Context, userID, since int64) ([]model.SecretRecord, error) {
	const query = `SELECT id, payload, deleted, revision, updated_at
		FROM secrets WHERE user_id = $1 AND revision > $2 ORDER BY revision LIMIT $3`

	rows, err := s.pool.Query(ctx, query, userID, since, pullPageSize)
	if err != nil {
		return nil, fmt.Errorf("select changes: %w", err)
	}
	defer rows.Close()

	var (
		page  []model.SecretRecord
		bytes int
	)
	for rows.Next() {
		var rec model.SecretRecord
		if err := rows.Scan(&rec.ID, &rec.Payload, &rec.Deleted, &rec.Revision, &rec.UpdatedAt); err != nil {
			return nil, fmt.Errorf("scan change: %w", err)
		}

		page = append(page, rec)
		bytes += len(rec.Payload)
		// Первая запись берётся всегда, даже если она одна больше бюджета:
		// иначе синхронизация встала бы на ней навсегда.
		if bytes >= pullPageBytes {
			break
		}
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("read changes: %w", err)
	}
	return page, nil
}

// SaveSecret записывает шифротекст поверх версии baseRevision и возвращает новую ревизию.
//
// Ревизия пользователя увеличивается в той же транзакции под блокировкой строки
// пользователя, поэтому параллельные клиенты одного владельца получают плотную
// возрастающую нумерацию. Если запись успели изменить, возвращается ErrConflict
// с актуальной версией.
func (s *Storage) SaveSecret(ctx context.Context, userID int64, rec model.SecretRecord, baseRevision int64) (int64, error) {
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return 0, fmt.Errorf("begin transaction: %w", err)
	}
	defer func() {
		_ = tx.Rollback(ctx)
	}()

	var userRevision int64
	if err := tx.QueryRow(ctx, `SELECT revision FROM users WHERE id = $1 FOR UPDATE`, userID).Scan(&userRevision); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return 0, ErrUserNotFound
		}
		return 0, fmt.Errorf("lock user: %w", err)
	}

	current, err := currentSecret(ctx, tx, userID, rec.ID)
	switch {
	case errors.Is(err, ErrSecretNotFound):
		if baseRevision != 0 {
			return 0, &ConflictError{}
		}
	case err != nil:
		return 0, err
	case current.Revision != baseRevision:
		return 0, &ConflictError{Current: current}
	}

	const updateUser = `UPDATE users SET revision = revision + 1 WHERE id = $1 RETURNING revision`
	var revision int64
	if err := tx.QueryRow(ctx, updateUser, userID).Scan(&revision); err != nil {
		return 0, fmt.Errorf("bump revision: %w", err)
	}

	// Отметка об удалении не несёт полезной нагрузки, но колонка объявлена
	// NOT NULL: nil превратился бы в SQL NULL и удаление не сохранилось бы.
	if rec.Payload == nil {
		rec.Payload = []byte{}
	}

	const upsert = `INSERT INTO secrets (user_id, id, revision, payload, deleted, updated_at)
		VALUES ($1, $2, $3, $4, $5, now())
		ON CONFLICT (user_id, id) DO UPDATE
		SET revision = EXCLUDED.revision, payload = EXCLUDED.payload,
		    deleted = EXCLUDED.deleted, updated_at = EXCLUDED.updated_at`
	if _, err := tx.Exec(ctx, upsert, userID, rec.ID, revision, rec.Payload, rec.Deleted); err != nil {
		return 0, fmt.Errorf("upsert secret: %w", err)
	}

	if err := tx.Commit(ctx); err != nil {
		return 0, fmt.Errorf("commit transaction: %w", err)
	}
	return revision, nil
}

func currentSecret(ctx context.Context, tx pgx.Tx, userID int64, id string) (model.SecretRecord, error) {
	const query = `SELECT id, payload, deleted, revision, updated_at
		FROM secrets WHERE user_id = $1 AND id = $2`

	var rec model.SecretRecord
	err := tx.QueryRow(ctx, query, userID, id).Scan(
		&rec.ID, &rec.Payload, &rec.Deleted, &rec.Revision, &rec.UpdatedAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return model.SecretRecord{}, ErrSecretNotFound
	}
	if err != nil {
		return model.SecretRecord{}, fmt.Errorf("select current secret: %w", err)
	}
	return rec, nil
}

// ConflictError сообщает, что запись изменили раньше: внутри лежит версия,
// которую клиент ещё не видел.
type ConflictError struct {
	Current model.SecretRecord
}

// Error реализует интерфейс error.
func (e *ConflictError) Error() string {
	return "secret revision conflict"
}

func migrate(dsn string) error {
	db, err := sql.Open("pgx", dsn)
	if err != nil {
		return fmt.Errorf("open database for migrations: %w", err)
	}
	defer func() {
		_ = db.Close()
	}()

	goose.SetBaseFS(migrationsFS)
	goose.SetLogger(goose.NopLogger())
	if err := goose.SetDialect("postgres"); err != nil {
		return fmt.Errorf("set migration dialect: %w", err)
	}
	if err := goose.Up(db, "migrations"); err != nil {
		return fmt.Errorf("apply migrations: %w", err)
	}
	return nil
}
