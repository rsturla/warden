package bridge

import (
	"context"
	"crypto/tls"
	"net"
)

type TLSDialer struct {
	Addr      string
	TLSConfig *tls.Config
}

func (d *TLSDialer) Dial(ctx context.Context) (net.Conn, error) {
	dialer := &tls.Dialer{Config: d.TLSConfig}
	return dialer.DialContext(ctx, "tcp", d.Addr)
}
