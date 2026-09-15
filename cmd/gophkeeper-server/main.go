// Команда gophkeeper-server поднимает gRPC-сервер GophKeeper.
package main

import (
	"context"
	"errors"
	"flag"
	"net"
	"os"
	"os/signal"
	"syscall"
	"time"

	"go.uber.org/zap"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"

	"github.com/superserj/gophkeeper/internal/server/auth"
	"github.com/superserj/gophkeeper/internal/server/config"
	"github.com/superserj/gophkeeper/internal/server/grpcapi"
	"github.com/superserj/gophkeeper/internal/server/service"
	"github.com/superserj/gophkeeper/internal/server/storage"
	"github.com/superserj/gophkeeper/internal/transport"
	pb "github.com/superserj/gophkeeper/proto/gophkeeper/v1"
)

// shutdownTimeout ограничивает ожидание завершения запросов при остановке:
// незакрытый клиентом поток Upload иначе держал бы сервер бесконечно.
const shutdownTimeout = 30 * time.Second

func main() {
	logger, err := zap.NewProduction()
	if err != nil {
		panic(err)
	}
	defer func() {
		_ = logger.Sync()
	}()

	if err := run(logger); err != nil {
		logger.Fatal("server stopped", zap.Error(err))
	}
}

func run(logger *zap.Logger) error {
	cfg, err := config.Parse(os.Args[1:])
	if err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return nil
		}
		return err
	}

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM, syscall.SIGQUIT)
	defer stop()

	store, err := storage.New(ctx, cfg.DatabaseURI)
	if err != nil {
		return err
	}
	defer store.Close()

	tokens := auth.NewTokenManager(cfg.JWTSecret, auth.TokenTTL)
	svc := service.New(store, tokens)

	creds, err := credentials.NewServerTLSFromFile(cfg.CertFile, cfg.KeyFile)
	if err != nil {
		return err
	}

	opts := append(transport.ServerOptions(),
		grpc.Creds(creds),
		grpc.UnaryInterceptor(grpcapi.UnaryAuthInterceptor(tokens)),
		grpc.StreamInterceptor(grpcapi.StreamAuthInterceptor(tokens)),
	)
	server := grpc.NewServer(opts...)
	pb.RegisterAuthServiceServer(server, grpcapi.NewAuthService(svc))
	pb.RegisterVaultServiceServer(server, grpcapi.NewVaultService(svc))

	listener, err := net.Listen("tcp", cfg.Address)
	if err != nil {
		return err
	}

	errs := make(chan error, 1)
	go func() {
		logger.Info("grpc server started", zap.String("address", cfg.Address))
		errs <- server.Serve(listener)
	}()

	select {
	case err := <-errs:
		return err
	case <-ctx.Done():
		logger.Info("shutting down")
		stopped := make(chan struct{})
		go func() {
			server.GracefulStop()
			close(stopped)
		}()

		select {
		case <-stopped:
		case <-time.After(shutdownTimeout):
			logger.Warn("graceful shutdown timed out, stopping now")
			server.Stop()
		}
		return nil
	}
}
