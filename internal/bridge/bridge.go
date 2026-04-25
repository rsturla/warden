package bridge

import (
	"context"
	"io"
	"log/slog"
	"net"
	"sync"
)

type Dialer interface {
	Dial(ctx context.Context) (net.Conn, error)
}

type Bridge struct {
	listener net.Listener
	dialer   Dialer
	logger   *slog.Logger
}

func New(listener net.Listener, dialer Dialer, logger *slog.Logger) *Bridge {
	return &Bridge{
		listener: listener,
		dialer:   dialer,
		logger:   logger,
	}
}

func (b *Bridge) Serve(ctx context.Context) error {
	go func() {
		<-ctx.Done()
		_ = b.listener.Close()
	}()

	for {
		conn, err := b.listener.Accept()
		if err != nil {
			if ctx.Err() != nil {
				return nil
			}
			b.logger.Error("accept failed", "error", err)
			continue
		}
		go b.handle(ctx, conn)
	}
}

func (b *Bridge) handle(ctx context.Context, clientConn net.Conn) {
	defer clientConn.Close()

	upstreamConn, err := b.dialer.Dial(ctx)
	if err != nil {
		b.logger.Error("upstream dial failed", "error", err)
		return
	}
	defer upstreamConn.Close()

	var wg sync.WaitGroup
	wg.Go(func() {
		_, _ = io.Copy(upstreamConn, clientConn)
		if tc, ok := upstreamConn.(*net.TCPConn); ok {
			_ = tc.CloseWrite()
		}
	})
	wg.Go(func() {
		_, _ = io.Copy(clientConn, upstreamConn)
		if tc, ok := clientConn.(*net.TCPConn); ok {
			_ = tc.CloseWrite()
		}
	})
	wg.Wait()
}
