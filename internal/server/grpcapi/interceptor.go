// Package grpcapi публикует сервисы GophKeeper по gRPC.
package grpcapi

import (
	"context"
	"strings"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"

	"github.com/superserj/gophkeeper/internal/server/auth"
)

type contextKey int

const userIDKey contextKey = iota

// Заголовок и префикс, в которых клиент передаёт токен.
const (
	authorizationHeader = "authorization"
	bearerPrefix        = "Bearer "
)

// publicMethods не требуют токена: клиент вызывает их до входа.
var publicMethods = map[string]bool{
	"/gophkeeper.v1.AuthService/Register": true,
	"/gophkeeper.v1.AuthService/GetSalts": true,
	"/gophkeeper.v1.AuthService/Login":    true,
}

// Authenticator проверяет токены доступа.
type Authenticator interface {
	Parse(token string) (int64, error)
}

// UnaryAuthInterceptor проверяет токен у одиночных вызовов.
func UnaryAuthInterceptor(a Authenticator) grpc.UnaryServerInterceptor {
	return func(ctx context.Context, req any, info *grpc.UnaryServerInfo, handler grpc.UnaryHandler) (any, error) {
		if publicMethods[info.FullMethod] {
			return handler(ctx, req)
		}
		userID, err := userFromContext(ctx, a)
		if err != nil {
			return nil, err
		}
		return handler(WithUserID(ctx, userID), req)
	}
}

// StreamAuthInterceptor проверяет токен у потоковых вызовов.
func StreamAuthInterceptor(a Authenticator) grpc.StreamServerInterceptor {
	return func(srv any, ss grpc.ServerStream, info *grpc.StreamServerInfo, handler grpc.StreamHandler) error {
		if publicMethods[info.FullMethod] {
			return handler(srv, ss)
		}
		userID, err := userFromContext(ss.Context(), a)
		if err != nil {
			return err
		}
		return handler(srv, &authenticatedStream{ServerStream: ss, ctx: WithUserID(ss.Context(), userID)})
	}
}

// WithUserID кладёт идентификатор пользователя в контекст.
func WithUserID(ctx context.Context, userID int64) context.Context {
	return context.WithValue(ctx, userIDKey, userID)
}

// UserID достаёт идентификатор пользователя из контекста.
func UserID(ctx context.Context) (int64, bool) {
	userID, ok := ctx.Value(userIDKey).(int64)
	return userID, ok
}

func userFromContext(ctx context.Context, a Authenticator) (int64, error) {
	md, ok := metadata.FromIncomingContext(ctx)
	if !ok {
		return 0, status.Error(codes.Unauthenticated, "missing metadata")
	}
	values := md.Get(authorizationHeader)
	if len(values) == 0 {
		return 0, status.Error(codes.Unauthenticated, "missing token")
	}

	token := strings.TrimPrefix(values[0], bearerPrefix)
	userID, err := a.Parse(token)
	if err != nil {
		return 0, status.Error(codes.Unauthenticated, auth.ErrBadToken.Error())
	}
	return userID, nil
}

// authenticatedStream подменяет контекст потока на обогащённый идентификатором.
type authenticatedStream struct {
	grpc.ServerStream
	ctx context.Context
}

// Context возвращает контекст с идентификатором пользователя.
func (s *authenticatedStream) Context() context.Context {
	return s.ctx
}
