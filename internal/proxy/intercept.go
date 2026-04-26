package proxy

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"time"

	"github.com/rsturla/warden/internal/policy"
	"github.com/rsturla/warden/internal/secrets"
	"github.com/rsturla/warden/internal/telemetry"
)

func (p *Proxy) handleInterceptConnect(conn net.Conn, req *http.Request, decision *policy.PolicyDecision, rt *resolvedTenant, start time.Time) {
	ctx := req.Context()
	token, ttl, err := p.resolveCredential(ctx, decision.Intercept.Credential, rt.secrets)
	if err != nil {
		p.logDeny(ctx, req, &policy.PolicyDecision{
			RuleName: decision.RuleName,
			Reason:   "secret_resolution_failed",
		}, rt.id, start)
		writeHTTPError(conn, http.StatusForbidden, "secret resolution failed")
		return
	}

	body := buildTokenResponse(token, ttl)
	resp := &http.Response{
		StatusCode:    http.StatusOK,
		ProtoMajor:    1,
		ProtoMinor:    1,
		Header:        make(http.Header),
		ContentLength: int64(len(body)),
		Body:          io.NopCloser(bytes.NewReader(body)),
	}
	resp.Header.Set("Content-Type", "application/json")
	if err := resp.Write(conn); err != nil {
		return
	}

	p.logIntercept(ctx, req, decision, rt.id, start)
}

func (p *Proxy) handleInterceptForward(w http.ResponseWriter, req *http.Request, decision *policy.PolicyDecision, rt *resolvedTenant, start time.Time) {
	ctx := req.Context()
	token, ttl, err := p.resolveCredential(ctx, decision.Intercept.Credential, rt.secrets)
	if err != nil {
		p.logDeny(ctx, req, &policy.PolicyDecision{
			RuleName: decision.RuleName,
			Reason:   "secret_resolution_failed",
		}, rt.id, start)
		p.writeError(w, http.StatusForbidden, "secret resolution failed")
		return
	}

	body := buildTokenResponse(token, ttl)
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(body)

	p.logIntercept(ctx, req, decision, rt.id, start)
}

func (p *Proxy) resolveCredential(ctx context.Context, name string, chain *secrets.Chain) (string, time.Duration, error) {
	val, ttl, ok, err := chain.ResolveWithTTL(ctx, name)
	if err != nil {
		return "", 0, err
	}
	if !ok {
		return "", 0, &credentialNotFoundError{name: name}
	}
	return val, ttl, nil
}

type credentialNotFoundError struct {
	name string
}

func (e *credentialNotFoundError) Error() string {
	return "credential not found: " + e.name
}

func buildTokenResponse(token string, ttl time.Duration) []byte {
	expiresIn := 3600
	if ttl > 0 {
		expiresIn = int(ttl.Seconds())
	}
	body, _ := json.Marshal(map[string]any{
		"access_token": token,
		"token_type":   "Bearer",
		"expires_in":   expiresIn,
	})
	return body
}

func (p *Proxy) logIntercept(ctx context.Context, r *http.Request, d *policy.PolicyDecision, tenantID string, start time.Time) {
	if p.telemetry == nil {
		return
	}
	_ = p.telemetry.LogRequest(ctx, telemetry.RequestLog{
		TenantID:        tenantID,
		ClientIP:        clientIP(r),
		Host:            requestHost(r),
		Method:          r.Method,
		Path:            r.URL.Path,
		Policy:          d.RuleName,
		Action:          "intercept",
		InjectedSecrets: []string{d.Intercept.Credential},
		UpstreamStatus:  http.StatusOK,
		DurationMs:      time.Since(start).Milliseconds(),
	})
}
