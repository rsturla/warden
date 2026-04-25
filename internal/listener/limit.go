package listener

import (
	"net"
	"sync"
)

type limitedListener struct {
	net.Listener
	sem chan struct{}
	wg  sync.WaitGroup
}

func WithMaxConnections(l net.Listener, max int) net.Listener {
	if max <= 0 {
		return l
	}
	return &limitedListener{
		Listener: l,
		sem:      make(chan struct{}, max),
	}
}

func (l *limitedListener) Accept() (net.Conn, error) {
	l.sem <- struct{}{}
	conn, err := l.Listener.Accept()
	if err != nil {
		<-l.sem
		return nil, err
	}
	l.wg.Add(1)
	return &limitedConn{Conn: conn, release: func() {
		<-l.sem
		l.wg.Done()
	}}, nil
}

type limitedConn struct {
	net.Conn
	once    sync.Once
	release func()
}

func (c *limitedConn) Close() error {
	err := c.Conn.Close()
	c.once.Do(c.release)
	return err
}
