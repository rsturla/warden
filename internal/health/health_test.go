package health

import (
	"context"
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

type stubLister struct {
	ids []string
}

func (s *stubLister) List(_ context.Context) ([]string, error) {
	return s.ids, nil
}

func TestTenantzSingleTenant(t *testing.T) {
	s := New()
	srv := httptest.NewServer(s.Handler())
	defer srv.Close()

	resp, err := http.Get(srv.URL + "/tenantz")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != 404 {
		t.Errorf("status = %d, want 404", resp.StatusCode)
	}
}

func TestTenantzMultiTenant(t *testing.T) {
	s := New()
	s.SetTenants(&stubLister{ids: []string{"alpha", "beta"}})
	srv := httptest.NewServer(s.Handler())
	defer srv.Close()

	resp, err := http.Get(srv.URL + "/tenantz")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		t.Errorf("status = %d", resp.StatusCode)
	}

	var body map[string]any
	json.NewDecoder(resp.Body).Decode(&body)
	tenants, ok := body["tenants"].([]any)
	if !ok {
		t.Fatal("tenants field missing or wrong type")
	}
	if len(tenants) != 2 {
		t.Errorf("tenant count = %d, want 2", len(tenants))
	}
	count, _ := body["count"].(float64)
	if int(count) != 2 {
		t.Errorf("count = %v, want 2", body["count"])
	}
}

func TestTenantzEmpty(t *testing.T) {
	s := New()
	s.SetTenants(&stubLister{ids: []string{}})
	srv := httptest.NewServer(s.Handler())
	defer srv.Close()

	resp, err := http.Get(srv.URL + "/tenantz")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		t.Errorf("status = %d", resp.StatusCode)
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
