package proxy

import (
	"bufio"
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"time"

	"github.com/rsturla/warden/internal/inject"
	"github.com/rsturla/warden/internal/policy"
)

func (p *Proxy) handleConnect(w http.ResponseWriter, r *http.Request) {
	connectHost := r.Host

	host, port, err := net.SplitHostPort(connectHost)
	if err != nil {
		host = connectHost
		port = "443"
	}

	rt, err := p.tenants.Resolve(r)
	if err != nil {
		p.writeError(w, http.StatusForbidden, "tenant resolution failed")
		return
	}

	if !rt.policy.CanMatchHost(host) {
		start := time.Now()
		p.logDeny(r.Context(), r, &policy.PolicyDecision{Reason: "no_match"}, rt.id, start)
		p.writeError(w, http.StatusForbidden, "no matching policy")
		return
	}

	hj, ok := w.(http.Hijacker)
	if !ok {
		p.writeError(w, http.StatusInternalServerError, "hijack not supported")
		return
	}

	w.WriteHeader(http.StatusOK)

	clientConn, _, err := hj.Hijack()
	if err != nil {
		return
	}
	defer clientConn.Close()

	tlsConfig := &tls.Config{
		GetCertificate: func(hello *tls.ClientHelloInfo) (*tls.Certificate, error) {
			name := hello.ServerName
			if name == "" {
				name = host
			}
			return p.ca.GetOrCreateCert(name)
		},
	}
	tlsConn := tls.Server(clientConn, tlsConfig)
	if err := tlsConn.Handshake(); err != nil {
		return
	}
	defer tlsConn.Close()

	reader := bufio.NewReader(tlsConn)

	for {
		_ = tlsConn.SetReadDeadline(time.Now().Add(60 * time.Second))
		req, err := http.ReadRequest(reader)
		if err != nil {
			return
		}
		_ = tlsConn.SetReadDeadline(time.Time{})

		req.URL.Scheme = "https"
		req.URL.Host = connectHost
		req.RemoteAddr = r.RemoteAddr

		p.handleDecryptedRequest(tlsConn, req, host, port, rt)
	}
}

func (p *Proxy) handleDecryptedRequest(clientConn net.Conn, req *http.Request, host, port string, rt *resolvedTenant) {
	start := time.Now()
	ctx := req.Context()

	decision, err := rt.policy.Evaluate(ctx, &policy.RequestContext{
		Host:   host,
		Path:   req.URL.Path,
		Method: req.Method,
	})
	if err != nil {
		writeHTTPError(clientConn, http.StatusInternalServerError, "policy evaluation error")
		return
	}

	if !decision.Allowed {
		p.logDeny(ctx, req, decision, rt.id, start)
		writeHTTPError(clientConn, http.StatusForbidden, denyMessage(decision))
		return
	}

	var injectResult *inject.Result
	if decision.Inject != nil {
		injectResult, err = inject.Apply(ctx, req, decision.Inject, rt.secrets)
		if err != nil {
			p.logDeny(ctx, req, &policy.PolicyDecision{
				RuleName: decision.RuleName,
				Reason:   "secret_resolution_failed",
			}, rt.id, start)
			writeHTTPError(clientConn, http.StatusForbidden, "secret resolution failed")
			return
		}
	}

	removeHopByHopHeaders(req.Header)
	req.RequestURI = ""

	upstreamConn, err := p.dialUpstream(ctx, host, port)
	if err != nil {
		writeHTTPError(clientConn, http.StatusBadGateway, "upstream connection failed")
		return
	}
	defer upstreamConn.Close()

	if err := req.Write(upstreamConn); err != nil {
		writeHTTPError(clientConn, http.StatusBadGateway, "upstream write failed")
		return
	}

	resp, err := http.ReadResponse(bufio.NewReader(upstreamConn), req)
	if err != nil {
		writeHTTPError(clientConn, http.StatusBadGateway, "upstream read failed")
		return
	}
	defer resp.Body.Close()

	removeHopByHopHeaders(resp.Header)
	if err := resp.Write(clientConn); err != nil {
		return
	}

	p.logAllow(ctx, req, decision, injectResult, rt.id, resp.StatusCode, start)
}

func (p *Proxy) dialUpstream(ctx context.Context, host, port string) (net.Conn, error) {
	ips, err := p.resolver.Resolve(ctx, host)
	if err != nil {
		return nil, err
	}
	if len(ips) == 0 {
		return nil, fmt.Errorf("no addresses resolved for %s", host)
	}
	if err := p.denylist.Check(host, ips); err != nil {
		return nil, err
	}

	addr := net.JoinHostPort(ips[0].String(), port)
	dialer := &net.Dialer{Timeout: 5 * time.Second}
	tcpConn, err := dialer.DialContext(ctx, "tcp", addr)
	if err != nil {
		return nil, err
	}

	tlsCfg := &tls.Config{
		ServerName: host,
		MinVersion: tls.VersionTLS12,
	}
	if p.transport.TLSClientConfig != nil && p.transport.TLSClientConfig.RootCAs != nil {
		tlsCfg.RootCAs = p.transport.TLSClientConfig.RootCAs
	}

	tlsConn := tls.Client(tcpConn, tlsCfg)
	if err := tlsConn.HandshakeContext(ctx); err != nil {
		_ = tcpConn.Close()
		return nil, err
	}
	return tlsConn, nil
}

func writeHTTPError(conn net.Conn, code int, msg string) {
	body, _ := json.Marshal(map[string]string{"error": msg})
	resp := &http.Response{
		StatusCode:    code,
		ProtoMajor:    1,
		ProtoMinor:    1,
		Header:        make(http.Header),
		ContentLength: int64(len(body)),
		Body:          io.NopCloser(bytes.NewReader(body)),
	}
	resp.Header.Set("Content-Type", "application/json")
	resp.Header.Set("Connection", "close")
	_ = resp.Write(conn)
}
