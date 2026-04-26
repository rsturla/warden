package proxy

import (
	"context"
	"encoding/json"
	"net"
	"net/http"
	"time"

	"github.com/rsturla/warden/internal/inject"
	"github.com/rsturla/warden/internal/policy"
	"github.com/rsturla/warden/internal/telemetry"
)

func (p *Proxy) handleForward(w http.ResponseWriter, r *http.Request) {
	start := time.Now()
	ctx := r.Context()

	rt, err := p.tenants.Resolve(r)
	if err != nil {
		p.writeError(w, http.StatusForbidden, "tenant resolution failed")
		return
	}

	host := r.URL.Hostname()
	if host == "" {
		host = r.Host
	}

	decision, err := rt.policy.Evaluate(ctx, &policy.RequestContext{
		Host:   host,
		Path:   r.URL.Path,
		Method: r.Method,
	})
	if err != nil {
		p.writeError(w, http.StatusInternalServerError, "policy evaluation error")
		return
	}

	if !decision.Allowed {
		p.logDeny(ctx, r, decision, rt.id, start)
		p.writeError(w, http.StatusForbidden, denyMessage(decision))
		return
	}

	var injectResult *inject.Result
	if decision.Inject != nil {
		injectResult, err = inject.Apply(ctx, r, decision.Inject, rt.secrets)
		if err != nil {
			p.logDeny(ctx, r, &policy.PolicyDecision{
				RuleName: decision.RuleName,
				Reason:   "secret_resolution_failed",
			}, rt.id, start)
			p.writeError(w, http.StatusForbidden, "secret resolution failed")
			return
		}
	}

	removeHopByHopHeaders(r.Header)

	r.RequestURI = ""

	resp, err := p.transport.RoundTrip(r)
	if err != nil {
		p.writeError(w, http.StatusBadGateway, "upstream connection failed")
		return
	}
	defer resp.Body.Close()

	removeHopByHopHeaders(resp.Header)

	for k, vv := range resp.Header {
		for _, v := range vv {
			w.Header().Add(k, v)
		}
	}
	w.WriteHeader(resp.StatusCode)
	_ = http.NewResponseController(w).Flush()
	_ = copyBody(w, resp.Body)

	p.logAllow(ctx, r, decision, injectResult, rt.id, resp.StatusCode, start)
}

func (p *Proxy) logAllow(ctx context.Context, r *http.Request, d *policy.PolicyDecision, inj *inject.Result, tenantID string, status int, start time.Time) {
	if p.telemetry == nil {
		return
	}
	entry := telemetry.RequestLog{
		TenantID:       tenantID,
		ClientIP:       clientIP(r),
		Host:           requestHost(r),
		Method:         r.Method,
		Path:           r.URL.Path,
		Policy:         d.RuleName,
		Action:         "allow",
		UpstreamStatus: status,
		DurationMs:     time.Since(start).Milliseconds(),
	}
	if inj != nil {
		entry.InjectedSecrets = inj.InjectedSecretNames
	}
	_ = p.telemetry.LogRequest(ctx, entry)
}

func (p *Proxy) logDeny(ctx context.Context, r *http.Request, d *policy.PolicyDecision, tenantID string, start time.Time) {
	if p.telemetry == nil {
		return
	}
	reason := d.Reason
	if reason == "" {
		reason = "no_match"
	}
	_ = p.telemetry.LogRequest(ctx, telemetry.RequestLog{
		TenantID:   tenantID,
		ClientIP:   clientIP(r),
		Host:       requestHost(r),
		Method:     r.Method,
		Path:       r.URL.Path,
		Policy:     d.RuleName,
		Action:     "deny",
		Reason:     reason,
		DurationMs: time.Since(start).Milliseconds(),
	})
}

func (p *Proxy) writeError(w http.ResponseWriter, code int, msg string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(map[string]string{"error": msg})
}

func denyMessage(d *policy.PolicyDecision) string {
	if d.RuleName != "" {
		return "denied by policy: " + d.RuleName
	}
	return "no matching policy"
}

func clientIP(r *http.Request) string {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return host
}

func requestHost(r *http.Request) string {
	if r.URL.Hostname() != "" {
		return r.URL.Hostname()
	}
	return r.Host
}
