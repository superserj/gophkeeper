package grpcapi

import (
	"context"
	"errors"

	"go.uber.org/zap"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/superserj/gophkeeper/internal/server/service"
	pb "github.com/superserj/gophkeeper/proto/gophkeeper/v1"
)

// AuthService принимает регистрацию и вход.
type AuthService struct {
	pb.UnimplementedAuthServiceServer

	svc    *service.Service
	logger *zap.Logger
}

// NewAuthService создаёт gRPC-обёртку над сервисом. Логгер передаётся явно:
// компонент пишет в него под своим именем и не зависит от глобального состояния.
func NewAuthService(svc *service.Service, logger *zap.Logger) *AuthService {
	return &AuthService{svc: svc, logger: named(logger, "auth")}
}

// Register заводит пользователя и выдаёт токен.
func (s *AuthService) Register(ctx context.Context, req *pb.RegisterRequest) (*pb.AuthResponse, error) {
	session, err := s.svc.Register(ctx, service.Credentials{
		Login:      req.GetLogin(),
		AuthKey:    req.GetAuthKey(),
		SaltAuth:   req.GetSaltAuth(),
		SaltData:   req.GetSaltData(),
		KDFVersion: req.GetKdfVersion(),
		Verifier:   req.GetVerifier(),
	})
	if err != nil {
		return nil, s.fail("register", err)
	}
	return sessionResponse(session), nil
}

// GetSalts отдаёт соль аутентификации: она нужна клиенту до входа.
func (s *AuthService) GetSalts(ctx context.Context, req *pb.GetSaltsRequest) (*pb.GetSaltsResponse, error) {
	salts, err := s.svc.Salts(ctx, req.GetLogin())
	if err != nil {
		return nil, s.fail("get salts", err)
	}
	return &pb.GetSaltsResponse{SaltAuth: salts.SaltAuth, KdfVersion: salts.KDFVersion}, nil
}

// Login проверяет ключ аутентификации и выдаёт токен.
func (s *AuthService) Login(ctx context.Context, req *pb.LoginRequest) (*pb.AuthResponse, error) {
	session, err := s.svc.Login(ctx, req.GetLogin(), req.GetAuthKey())
	if err != nil {
		return nil, s.fail("login", err)
	}
	return sessionResponse(session), nil
}

func sessionResponse(session service.Session) *pb.AuthResponse {
	return &pb.AuthResponse{
		Token:      session.Token,
		SaltAuth:   session.SaltAuth,
		SaltData:   session.SaltData,
		KdfVersion: session.KDFVersion,
		Verifier:   session.Verifier,
	}
}

// fail переводит ошибку в статус и логирует внутренние причины: клиенту
// детали отдавать нельзя, но без записи в журнал поломка осталась бы незаметной.
func (s *AuthService) fail(op string, err error) error {
	st := authError(err)
	if status.Code(st) == codes.Internal {
		s.logger.Error(op, zap.Error(err))
	}
	return st
}

func authError(err error) error {
	switch {
	case errors.Is(err, service.ErrLoginTaken):
		return status.Error(codes.AlreadyExists, "login already taken")
	case errors.Is(err, service.ErrBadCredentials):
		return status.Error(codes.Unauthenticated, "invalid credentials")
	case errors.Is(err, service.ErrEmptyLogin):
		return status.Error(codes.InvalidArgument, "login is empty")
	case errors.Is(err, service.ErrBusy):
		return status.Error(codes.ResourceExhausted, "server is busy, try again later")
	default:
		return status.Error(codes.Internal, "internal error")
	}
}
