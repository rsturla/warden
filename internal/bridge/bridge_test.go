package bridge

import (
	"context"
	"io"
	"log/slog"
	"net"
	"testing"
	"time"
)

type tcpDialer struct {
	addr string
}

func (d *tcpDialer) Dial(_ context.Context) (net.Conn, error) {
	return net.Dial("tcp", d.addr)
}

func TestBridgeForwardsData(t *testing.T) {
	// Upstream echo server
	upstream, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer upstream.Close()

	go func() {
		for {
			conn, err := upstream.Accept()
			if err != nil {
				return
			}
			go func() {
				defer conn.Close()
				io.Copy(conn, conn) // echo
			}()
		}
	}()

	// Bridge listener
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}

	b := New(listener, &tcpDialer{addr: upstream.Addr().String()}, slog.Default())

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go b.Serve(ctx)

	// Connect through bridge
	conn, err := net.Dial("tcp", listener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()

	msg := "hello warden"
	conn.Write([]byte(msg))
	conn.(*net.TCPConn).CloseWrite()

	buf, err := io.ReadAll(conn)
	if err != nil {
		t.Fatal(err)
	}
	if string(buf) != msg {
		t.Errorf("got %q, want %q", buf, msg)
	}
}

func TestBridgeConcurrent(t *testing.T) {
	upstream, _ := net.Listen("tcp", "127.0.0.1:0")
	defer upstream.Close()

	go func() {
		for {
			conn, err := upstream.Accept()
			if err != nil {
				return
			}
			go func() {
				defer conn.Close()
				io.Copy(conn, conn)
			}()
		}
	}()

	listener, _ := net.Listen("tcp", "127.0.0.1:0")
	b := New(listener, &tcpDialer{addr: upstream.Addr().String()}, slog.Default())

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go b.Serve(ctx)

	done := make(chan bool, 10)
	for i := range 10 {
		go func(id int) {
			conn, err := net.Dial("tcp", listener.Addr().String())
			if err != nil {
				t.Error(err)
				done <- false
				return
			}
			defer conn.Close()

			msg := []byte("concurrent test")
			conn.Write(msg)
			conn.(*net.TCPConn).CloseWrite()

			buf, _ := io.ReadAll(conn)
			done <- string(buf) == string(msg)
		}(i)
	}

	for range 10 {
		if !<-done {
			t.Error("concurrent bridge failed")
		}
	}
}

func TestBridgeUpstreamDialFailure(t *testing.T) {
	listener, _ := net.Listen("tcp", "127.0.0.1:0")
	// Dial to a port nothing listens on
	b := New(listener, &tcpDialer{addr: "127.0.0.1:1"}, slog.Default())

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go b.Serve(ctx)

	conn, err := net.Dial("tcp", listener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()

	// Connection should close quickly when upstream dial fails
	conn.SetReadDeadline(time.Now().Add(2 * time.Second))
	buf := make([]byte, 1)
	_, err = conn.Read(buf)
	if err == nil {
		t.Error("expected read error after upstream dial failure")
	}
}

func TestBridgeGracefulShutdown(t *testing.T) {
	upstream, _ := net.Listen("tcp", "127.0.0.1:0")
	defer upstream.Close()

	go func() {
		for {
			conn, err := upstream.Accept()
			if err != nil {
				return
			}
			go func() {
				defer conn.Close()
				io.Copy(conn, conn)
			}()
		}
	}()

	listener, _ := net.Listen("tcp", "127.0.0.1:0")
	b := New(listener, &tcpDialer{addr: upstream.Addr().String()}, slog.Default())

	ctx, cancel := context.WithCancel(context.Background())
	errCh := make(chan error, 1)
	go func() { errCh <- b.Serve(ctx) }()

	cancel()

	select {
	case err := <-errCh:
		if err != nil {
			t.Errorf("expected nil error on shutdown, got %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("shutdown timed out")
	}
}
