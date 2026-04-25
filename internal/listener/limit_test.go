package listener

import (
	"net"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func TestWithMaxConnectionsLimit(t *testing.T) {
	base, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer base.Close()

	limited := WithMaxConnections(base, 2)
	addr := limited.Addr().String()

	var active atomic.Int32
	var maxSeen atomic.Int32

	var wg sync.WaitGroup
	go func() {
		for {
			conn, err := limited.Accept()
			if err != nil {
				return
			}
			wg.Add(1)
			go func() {
				defer wg.Done()
				defer conn.Close()
				cur := active.Add(1)
				for {
					old := maxSeen.Load()
					if cur <= old || maxSeen.CompareAndSwap(old, cur) {
						break
					}
				}
				time.Sleep(50 * time.Millisecond)
				active.Add(-1)
			}()
		}
	}()

	for range 5 {
		conn, err := net.Dial("tcp", addr)
		if err != nil {
			t.Fatal(err)
		}
		defer conn.Close()
	}

	time.Sleep(200 * time.Millisecond)
	limited.Close()
	wg.Wait()

	if maxSeen.Load() > 2 {
		t.Errorf("max concurrent = %d, want <= 2", maxSeen.Load())
	}
}

func TestWithMaxConnectionsZero(t *testing.T) {
	base, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer base.Close()

	limited := WithMaxConnections(base, 0)
	if limited != base {
		t.Error("max=0 should return original listener")
	}
}

func TestWithMaxConnectionsNegative(t *testing.T) {
	base, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer base.Close()

	limited := WithMaxConnections(base, -1)
	if limited != base {
		t.Error("negative max should return original listener")
	}
}

func TestLimitedConnDoubleClose(t *testing.T) {
	base, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}

	limited := WithMaxConnections(base, 10)
	addr := limited.Addr().String()

	go func() {
		conn, err := limited.Accept()
		if err != nil {
			return
		}
		conn.Close()
		conn.Close() // double close should not panic
	}()

	conn, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatal(err)
	}
	conn.Close()
	time.Sleep(50 * time.Millisecond)
	limited.Close()
}
