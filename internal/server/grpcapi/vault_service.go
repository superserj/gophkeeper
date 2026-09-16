package grpcapi

import (
	"context"
	"errors"
	"io"
	"time"

	"golang.org/x/sync/semaphore"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/superserj/gophkeeper/internal/model"
	"github.com/superserj/gophkeeper/internal/server/service"
	"github.com/superserj/gophkeeper/internal/server/storage"
	"github.com/superserj/gophkeeper/internal/transport"
	pb "github.com/superserj/gophkeeper/proto/gophkeeper/v1"
)

// Ограничения приёма больших записей. Загрузка копит полезную нагрузку в памяти
// до конца потока, поэтому число одновременных загрузок и время их жизни
// ограничены: иначе клиент открыл бы сколько угодно потоков по MaxSecretSize
// каждый и исчерпал бы память сервера.
const (
	maxParallelUploads = 8
	uploadTimeout      = 2 * time.Minute
)

// VaultService отдаёт и принимает шифротексты пользователя.
type VaultService struct {
	pb.UnimplementedVaultServiceServer

	svc     *service.Service
	uploads *semaphore.Weighted
}

// NewVaultService создаёт gRPC-обёртку над сервисом.
func NewVaultService(svc *service.Service) *VaultService {
	return &VaultService{svc: svc, uploads: semaphore.NewWeighted(maxParallelUploads)}
}

// Push сохраняет запись поверх известной клиенту ревизии.
func (s *VaultService) Push(ctx context.Context, req *pb.PushRequest) (*pb.PushResponse, error) {
	userID, ok := UserID(ctx)
	if !ok {
		return nil, status.Error(codes.Unauthenticated, "missing token")
	}

	revision, err := s.svc.Push(ctx, userID, model.SecretRecord{
		ID:      req.GetId(),
		Payload: req.GetPayload(),
		Deleted: req.GetDeleted(),
	}, req.GetBaseRevision())
	if err != nil {
		return nil, vaultError(err)
	}
	return &pb.PushResponse{Revision: revision}, nil
}

// Pull отдаёт изменения по возрастанию ревизии.
func (s *VaultService) Pull(req *pb.PullRequest, stream pb.VaultService_PullServer) error {
	userID, ok := UserID(stream.Context())
	if !ok {
		return status.Error(codes.Unauthenticated, "missing token")
	}

	err := s.svc.Pull(stream.Context(), userID, req.GetSince(), func(rec model.SecretRecord) error {
		return stream.Send(&pb.SecretChange{
			Id:              rec.ID,
			Payload:         rec.Payload,
			Deleted:         rec.Deleted,
			Revision:        rec.Revision,
			UpdatedAtUnixMs: rec.UpdatedAt.UnixMilli(),
		})
	})
	if err != nil {
		return vaultError(err)
	}
	return nil
}

// Upload принимает большую запись кусками: идентификатор и базовая ревизия
// приходят в первом сообщении, дальше идут только данные.
func (s *VaultService) Upload(stream pb.VaultService_UploadServer) error {
	userID, ok := UserID(stream.Context())
	if !ok {
		return status.Error(codes.Unauthenticated, "missing token")
	}

	if !s.uploads.TryAcquire(1) {
		return status.Error(codes.ResourceExhausted, "too many uploads, try again later")
	}
	defer s.uploads.Release(1)

	// Поток, в который перестали писать, держал бы слот и свой буфер сколько
	// угодно долго, поэтому у загрузки есть предельное время.
	ctx, cancel := context.WithTimeout(stream.Context(), uploadTimeout)
	defer cancel()

	var (
		id           string
		baseRevision int64
		payload      []byte
		first        = true
	)
	for {
		if err := ctx.Err(); err != nil {
			return status.Error(codes.DeadlineExceeded, "upload took too long")
		}

		chunk, err := stream.Recv()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return status.Error(codes.Internal, "receive chunk")
		}
		if first {
			id, baseRevision, first = chunk.GetId(), chunk.GetBaseRevision(), false
		}
		payload = append(payload, chunk.GetData()...)
		if len(payload) > model.MaxSecretSize {
			return status.Error(codes.InvalidArgument, "payload too large")
		}
	}
	if id == "" {
		return status.Error(codes.InvalidArgument, "secret id is empty")
	}

	revision, err := s.svc.Push(ctx, userID, model.SecretRecord{ID: id, Payload: payload}, baseRevision)
	if err != nil {
		return vaultError(err)
	}
	return stream.SendAndClose(&pb.PushResponse{Revision: revision})
}

// Download отдаёт запись кусками.
func (s *VaultService) Download(req *pb.DownloadRequest, stream pb.VaultService_DownloadServer) error {
	userID, ok := UserID(stream.Context())
	if !ok {
		return status.Error(codes.Unauthenticated, "missing token")
	}

	rec, err := s.svc.Get(stream.Context(), userID, req.GetId())
	if err != nil {
		return vaultError(err)
	}

	for offset := 0; offset < len(rec.Payload); offset += transport.ChunkSize {
		end := offset + transport.ChunkSize
		if end > len(rec.Payload) {
			end = len(rec.Payload)
		}
		if err := stream.Send(&pb.DownloadChunk{Data: rec.Payload[offset:end], Revision: rec.Revision}); err != nil {
			return status.Error(codes.Internal, "send chunk")
		}
	}
	return nil
}

func vaultError(err error) error {
	var conflict *storage.ConflictError
	if errors.As(err, &conflict) {
		return conflictStatus(conflict)
	}

	switch {
	case errors.Is(err, service.ErrNotFound):
		return status.Error(codes.NotFound, "secret not found")
	case errors.Is(err, service.ErrPayloadTooLarge):
		return status.Error(codes.InvalidArgument, "payload too large")
	default:
		return status.Error(codes.Internal, "internal error")
	}
}

// conflictStatus кладёт актуальную версию записи в детали ошибки, чтобы клиент
// показал пользователю обе версии и дал выбрать, какую оставить.
func conflictStatus(conflict *storage.ConflictError) error {
	st := status.New(codes.FailedPrecondition, "secret revision conflict")
	current := conflict.Current
	if current.ID == "" {
		return st.Err()
	}

	withDetails, err := st.WithDetails(&pb.Conflict{Current: &pb.SecretChange{
		Id:              current.ID,
		Payload:         current.Payload,
		Deleted:         current.Deleted,
		Revision:        current.Revision,
		UpdatedAtUnixMs: current.UpdatedAt.UnixMilli(),
	}})
	if err != nil {
		return st.Err()
	}
	return withDetails.Err()
}
