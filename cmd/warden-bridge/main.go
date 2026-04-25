package main

import (
	"context"
	"flag"
	"log/slog"
	"net"
	"os"
	"os/signal"
	"syscall"

	"github.com/rsturla/warden/internal/bridge"
)

func main() {
	listenAddr := flag.String("listen", "127.0.0.1:8080", "TCP listen address")
	vsockCID := flag.Uint("vsock-cid", 2, "vsock context ID (2 = host)")
	vsockPort := flag.Uint("vsock-port", 8080, "vsock port")
	flag.Parse()

	logger := slog.New(slog.NewJSONHandler(os.Stdout, nil))
	slog.SetDefault(logger)

	ctx, cancel := signal.NotifyContext(context.Background(), syscall.SIGTERM, syscall.SIGINT)
	defer cancel()

	l, err := net.Listen("tcp", *listenAddr)
	if err != nil {
		slog.Error("listen failed", "error", err)
		os.Exit(1)
	}

	dialer := &bridge.VsockDialer{
		CID:  uint32(*vsockCID),
		Port: uint32(*vsockPort),
	}

	b := bridge.New(l, dialer, logger)

	slog.Info("warden-bridge starting",
		"listen", *listenAddr,
		"vsock_cid", *vsockCID,
		"vsock_port", *vsockPort,
	)

	if err := b.Serve(ctx); err != nil {
		slog.Error("bridge error", "error", err)
		os.Exit(1)
	}
}
