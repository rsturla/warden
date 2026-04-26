package health

import (
	"context"
	"encoding/json"
	"net/http"
	"sync/atomic"
)

type TenantLister interface {
	List(ctx context.Context) ([]string, error)
}

type Server struct {
	ready   atomic.Bool
	tenants TenantLister
}

func New() *Server {
	return &Server{}
}

func (s *Server) SetTenants(t TenantLister) {
	s.tenants = t
}

func (s *Server) SetReady(v bool) {
	s.ready.Store(v)
}

func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /healthz", s.handleHealthz)
	mux.HandleFunc("GET /readyz", s.handleReadyz)
	mux.HandleFunc("GET /tenantz", s.handleTenantz)
	return mux
}

func (s *Server) handleHealthz(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]string{"status": "ok"})
}

func (s *Server) handleReadyz(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	if s.ready.Load() {
		_ = json.NewEncoder(w).Encode(map[string]string{"status": "ready"})
	} else {
		w.WriteHeader(http.StatusServiceUnavailable)
		_ = json.NewEncoder(w).Encode(map[string]string{"status": "not ready"})
	}
}

func (s *Server) handleTenantz(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	if s.tenants == nil {
		w.WriteHeader(http.StatusNotFound)
		_ = json.NewEncoder(w).Encode(map[string]string{"error": "single-tenant mode"})
		return
	}
	ids, err := s.tenants.List(r.Context())
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		_ = json.NewEncoder(w).Encode(map[string]string{"error": "failed to list tenants"})
		return
	}
	_ = json.NewEncoder(w).Encode(map[string]any{"tenants": ids, "count": len(ids)})
}
