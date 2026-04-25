package main

import (
	"context"
	"flag"
	"io"
	"log/slog"
	"net"
	"os"
	"os/signal"
	"sync"
	"syscall"

	"github.com/mdlayher/vsock"
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
	defer l.Close()

	slog.Info("warden-bridge starting",
		"listen", *listenAddr,
		"vsock_cid", *vsockCID,
		"vsock_port", *vsockPort,
	)

	go func() {
		<-ctx.Done()
		l.Close()
	}()

	for {
		conn, err := l.Accept()
		if err != nil {
			if ctx.Err() != nil {
				return
			}
			slog.Error("accept failed", "error", err)
			continue
		}
		go bridge(conn, uint32(*vsockCID), uint32(*vsockPort))
	}
}

func bridge(tcpConn net.Conn, cid, port uint32) {
	defer tcpConn.Close()

	vsockConn, err := vsock.Dial(cid, port, nil)
	if err != nil {
		slog.Error("vsock dial failed", "cid", cid, "port", port, "error", err)
		return
	}
	defer vsockConn.Close()

	var wg sync.WaitGroup
	wg.Go(func() { io.Copy(vsockConn, tcpConn) })
	wg.Go(func() { io.Copy(tcpConn, vsockConn) })
	wg.Wait()
}
