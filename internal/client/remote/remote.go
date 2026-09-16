// Package remote обращается к серверу GophKeeper по gRPC.
package remote

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"os"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"

	"github.com/superserj/gophkeeper/internal/model"
	"github.com/superserj/gophkeeper/internal/transport"
	pb "github.com/superserj/gophkeeper/proto/gophkeeper/v1"
)

// Ошибки, которые различает клиентская логика.
var (
	// ErrBadCredentials — неверный логин или мастер-пароль.
	ErrBadCredentials = errors.New("invalid login or master password")
	// ErrLoginTaken — логин уже занят.
	ErrLoginTaken = errors.New("login already taken")
	// ErrNotFound — записи нет на сервере.
	ErrNotFound = errors.New("secret not found")
)

// ConflictError означает, что запись изменили с другого клиента.
type ConflictError struct {
	// Current — версия записи, лежащая на сервере.
	Current model.SecretRecord
}

// Error реализует интерфейс error.
func (e *ConflictError) Error() string {
	return "secret was changed on the server"
}

// Session — данные, полученные при регистрации или входе.
type Session struct {
	Token      string
	SaltAuth   []byte
	SaltData   []byte
	KDFVersion uint32
	Verifier   []byte
}

// RegisterParams — то, что клиент отправляет при регистрации.
type RegisterParams struct {
	Login      string
	AuthKey    []byte
	SaltAuth   []byte
	SaltData   []byte
	KDFVersion uint32
	Verifier   []byte
}

// Client — соединение с сервером.
type Client struct {
	conn  *grpc.ClientConn
	auth  pb.AuthServiceClient
	vault pb.VaultServiceClient
	token *tokenHolder
}

// tokenHolder хранит токен между вызовами и подставляет его в метаданные.
type tokenHolder struct {
	value string
}

// Dial открывает соединение с сервером. caFile — корневой сертификат, которым
// подписан сертификат сервера; пустое значение означает системные корни.
func Dial(address, caFile string) (*Client, error) {
	tlsConfig := &tls.Config{MinVersion: tls.VersionTLS12}
	if caFile != "" {
		pem, err := os.ReadFile(caFile)
		if err != nil {
			return nil, fmt.Errorf("read ca certificate: %w", err)
		}
		pool := x509.NewCertPool()
		if !pool.AppendCertsFromPEM(pem) {
			return nil, errors.New("ca certificate is not valid")
		}
		tlsConfig.RootCAs = pool
	}

	opts := append(transport.DialOptions(), grpc.WithTransportCredentials(credentials.NewTLS(tlsConfig)))

	conn, err := grpc.NewClient(address, opts...)
	if err != nil {
		return nil, fmt.Errorf("connect to server: %w", err)
	}
	return Wrap(conn), nil
}

// Wrap оборачивает готовое соединение. Нужен там, где соединение создаётся
// отдельно, например поверх bufconn в тестах.
func Wrap(conn *grpc.ClientConn) *Client {
	return &Client{
		conn:  conn,
		auth:  pb.NewAuthServiceClient(conn),
		vault: pb.NewVaultServiceClient(conn),
		token: &tokenHolder{},
	}
}

// Close закрывает соединение.
func (c *Client) Close() error {
	return c.conn.Close()
}

// SetToken задаёт токен доступа для последующих вызовов.
func (c *Client) SetToken(token string) {
	c.token.value = token
}

// Register заводит пользователя на сервере.
func (c *Client) Register(ctx context.Context, p RegisterParams) (Session, error) {
	resp, err := c.auth.Register(c.token.withToken(ctx), &pb.RegisterRequest{
		Login:      p.Login,
		AuthKey:    p.AuthKey,
		SaltAuth:   p.SaltAuth,
		SaltData:   p.SaltData,
		KdfVersion: p.KDFVersion,
		Verifier:   p.Verifier,
	})
	if err != nil {
		return Session{}, convertError(err)
	}
	return session(resp), nil
}

// Salts запрашивает соль аутентификации до входа.
func (c *Client) Salts(ctx context.Context, login string) ([]byte, uint32, error) {
	resp, err := c.auth.GetSalts(c.token.withToken(ctx), &pb.GetSaltsRequest{Login: login})
	if err != nil {
		return nil, 0, convertError(err)
	}
	return resp.GetSaltAuth(), resp.GetKdfVersion(), nil
}

// Login входит по логину и ключу аутентификации.
func (c *Client) Login(ctx context.Context, login string, authKey []byte) (Session, error) {
	resp, err := c.auth.Login(c.token.withToken(ctx), &pb.LoginRequest{Login: login, AuthKey: authKey})
	if err != nil {
		return Session{}, convertError(err)
	}
	return session(resp), nil
}

// Push отправляет запись поверх известной клиенту ревизии.
func (c *Client) Push(ctx context.Context, rec model.SecretRecord, baseRevision int64) (int64, error) {
	resp, err := c.vault.Push(c.token.withToken(ctx), &pb.PushRequest{
		Id:           rec.ID,
		Payload:      rec.Payload,
		Deleted:      rec.Deleted,
		BaseRevision: baseRevision,
	})
	if err != nil {
		return 0, convertError(err)
	}
	return resp.GetRevision(), nil
}

// Pull передаёт в fn изменения с ревизией больше since по возрастанию.
func (c *Client) Pull(ctx context.Context, since int64, fn func(model.SecretRecord) error) error {
	stream, err := c.vault.Pull(c.token.withToken(ctx), &pb.PullRequest{Since: since})
	if err != nil {
		return convertError(err)
	}
	for {
		change, err := stream.Recv()
		if errors.Is(err, io.EOF) {
			return nil
		}
		if err != nil {
			return convertError(err)
		}
		rec := model.SecretRecord{
			ID:        change.GetId(),
			Payload:   change.GetPayload(),
			Deleted:   change.GetDeleted(),
			Revision:  change.GetRevision(),
			UpdatedAt: time.UnixMilli(change.GetUpdatedAtUnixMs()),
		}
		if err := fn(rec); err != nil {
			return err
		}
	}
}

// Upload отправляет запись кусками.
func (c *Client) Upload(ctx context.Context, id string, payload []byte, baseRevision int64) (int64, error) {
	stream, err := c.vault.Upload(c.token.withToken(ctx))
	if err != nil {
		return 0, convertError(err)
	}

	first := true
	for offset := 0; offset < len(payload) || first; offset += transport.ChunkSize {
		end := offset + transport.ChunkSize
		if end > len(payload) {
			end = len(payload)
		}
		chunk := &pb.UploadChunk{Data: payload[offset:end]}
		if first {
			chunk.Id, chunk.BaseRevision, first = id, baseRevision, false
		}
		if err := stream.Send(chunk); err != nil {
			return 0, convertError(err)
		}
	}

	resp, err := stream.CloseAndRecv()
	if err != nil {
		return 0, convertError(err)
	}
	return resp.GetRevision(), nil
}

// Download забирает запись кусками.
func (c *Client) Download(ctx context.Context, id string) ([]byte, int64, error) {
	stream, err := c.vault.Download(c.token.withToken(ctx), &pb.DownloadRequest{Id: id})
	if err != nil {
		return nil, 0, convertError(err)
	}

	var (
		payload  []byte
		revision int64
	)
	for {
		chunk, err := stream.Recv()
		if errors.Is(err, io.EOF) {
			return payload, revision, nil
		}
		if err != nil {
			return nil, 0, convertError(err)
		}
		payload = append(payload, chunk.GetData()...)
		revision = chunk.GetRevision()
	}
}

func session(resp *pb.AuthResponse) Session {
	return Session{
		Token:      resp.GetToken(),
		SaltAuth:   resp.GetSaltAuth(),
		SaltData:   resp.GetSaltData(),
		KDFVersion: resp.GetKdfVersion(),
		Verifier:   resp.GetVerifier(),
	}
}

// convertError переводит ошибку gRPC в доменную. Конфликт приходит с деталями,
// в которых лежит актуальная версия записи.
func convertError(err error) error {
	st, ok := status.FromError(err)
	if !ok {
		return err
	}

	switch st.Code() {
	case codes.AlreadyExists:
		return ErrLoginTaken
	case codes.Unauthenticated:
		return ErrBadCredentials
	case codes.NotFound:
		return ErrNotFound
	case codes.FailedPrecondition:
		return conflictFromStatus(st)
	default:
		return errors.New(st.Message())
	}
}

func conflictFromStatus(st *status.Status) error {
	conflict := &ConflictError{}
	for _, detail := range st.Details() {
		payload, ok := detail.(*pb.Conflict)
		if !ok || payload.GetCurrent() == nil {
			continue
		}
		current := payload.GetCurrent()
		conflict.Current = model.SecretRecord{
			ID:        current.GetId(),
			Payload:   current.GetPayload(),
			Deleted:   current.GetDeleted(),
			Revision:  current.GetRevision(),
			UpdatedAt: time.UnixMilli(current.GetUpdatedAtUnixMs()),
		}
	}
	return conflict
}

// withToken подставляет токен доступа в исходящие метаданные.
func (t *tokenHolder) withToken(ctx context.Context) context.Context {
	if t.value == "" {
		return ctx
	}
	return metadata.AppendToOutgoingContext(ctx, "authorization", "Bearer "+t.value)
}
