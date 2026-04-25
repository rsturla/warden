package health

import (
	"encoding/json"
	"net/http"
	"sync/atomic"
)

type Server struct {
	ready atomic.Bool
}

func New() *Server {
	return &Server{}
}

func (s *Server) SetReady(v bool) {
	s.ready.Store(v)
}

func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /healthz", s.handleHealthz)
	mux.HandleFunc("GET /readyz", s.handleReadyz)
	return mux
}

func (s *Server) handleHealthz(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{"status": "ok"})
}

func (s *Server) handleReadyz(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	if s.ready.Load() {
		json.NewEncoder(w).Encode(map[string]string{"status": "ready"})
	} else {
		w.WriteHeader(http.StatusServiceUnavailable)
		json.NewEncoder(w).Encode(map[string]string{"status": "not ready"})
	}
}
