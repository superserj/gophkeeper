// Package transport хранит общие для сервера и клиента настройки gRPC.
package transport

import "google.golang.org/grpc"

// MaxMessageSize поднимает дефолтный лимит gRPC (4 МиБ) выше максимального
// размера записи: иначе загруженный бинарный секрет нельзя было бы получить
// обратно потоком Pull, который передаёт запись одним сообщением.
const MaxMessageSize = 16 << 20

// ChunkSize — размер куска в потоках Upload и Download.
const ChunkSize = 64 << 10

// ServerOptions возвращает лимиты сообщений для grpc.NewServer.
func ServerOptions() []grpc.ServerOption {
	return []grpc.ServerOption{
		grpc.MaxRecvMsgSize(MaxMessageSize),
		grpc.MaxSendMsgSize(MaxMessageSize),
	}
}

// DialOptions возвращает лимиты сообщений для grpc.NewClient.
func DialOptions() []grpc.DialOption {
	return []grpc.DialOption{
		grpc.WithDefaultCallOptions(
			grpc.MaxCallRecvMsgSize(MaxMessageSize),
			grpc.MaxCallSendMsgSize(MaxMessageSize),
		),
	}
}
