package health

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestHealthz(t *testing.T) {
	s := New()
	srv := httptest.NewServer(s.Handler())
	defer srv.Close()

	resp, err := http.Get(srv.URL + "/healthz")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		t.Errorf("status = %d", resp.StatusCode)
	}

	var body map[string]string
	json.NewDecoder(resp.Body).Decode(&body)
	if body["status"] != "ok" {
		t.Errorf("status = %q", body["status"])
	}
}

func TestReadyzNotReady(t *testing.T) {
	s := New()
	srv := httptest.NewServer(s.Handler())
	defer srv.Close()

	resp, err := http.Get(srv.URL + "/readyz")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != 503 {
		t.Errorf("status = %d, want 503", resp.StatusCode)
	}
}

func TestReadyzReady(t *testing.T) {
	s := New()
	s.SetReady(true)
	srv := httptest.NewServer(s.Handler())
	defer srv.Close()

	resp, err := http.Get(srv.URL + "/readyz")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		t.Errorf("status = %d", resp.StatusCode)
	}
}

func TestReadyzToggle(t *testing.T) {
	s := New()
	srv := httptest.NewServer(s.Handler())
	defer srv.Close()

	s.SetReady(true)
	resp, _ := http.Get(srv.URL + "/readyz")
	resp.Body.Close()
	if resp.StatusCode != 200 {
		t.Error("should be ready")
	}

	s.SetReady(false)
	resp, _ = http.Get(srv.URL + "/readyz")
	resp.Body.Close()
	if resp.StatusCode != 503 {
		t.Error("should be not ready")
	}
}

func TestMethodNotAllowed(t *testing.T) {
	s := New()
	srv := httptest.NewServer(s.Handler())
	defer srv.Close()

	resp, err := http.Post(srv.URL+"/healthz", "application/json", nil)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()

	if resp.StatusCode != 405 {
		t.Errorf("POST /healthz status = %d, want 405", resp.StatusCode)
	}
}

func TestNotFound(t *testing.T) {
	s := New()
	srv := httptest.NewServer(s.Handler())
	defer srv.Close()

	resp, err := http.Get(srv.URL + "/unknown")
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()

	if resp.StatusCode != 404 {
		t.Errorf("status = %d, want 404", resp.StatusCode)
	}
}
