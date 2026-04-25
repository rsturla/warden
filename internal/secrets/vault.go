package secrets

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/rsturla/warden/internal/config"
)

func init() {
	Register("vault", func(cfg config.SecretConfig) (SecretSource, error) {
		mount := cfg.Vault.Mount
		if mount == "" {
			mount = "secret"
		}
		auth := cfg.Vault.Auth
		if auth == "" {
			auth = "token"
		}
		return NewVaultSource(VaultConfig{
			Address: cfg.Vault.Address,
			Mount:   mount,
			Prefix:  cfg.Vault.Prefix,
			Auth:    auth,
		})
	})
}

type VaultConfig struct {
	Address string
	Mount   string
	Prefix  string
	Auth    string // "token" or "kubernetes"
}

type VaultSource struct {
	client  *http.Client
	address string
	mount   string
	prefix  string

	mu     sync.RWMutex
	token  string
	expiry time.Time
	authFn func(ctx context.Context) (string, time.Duration, error)
}

func NewVaultSource(cfg VaultConfig) (*VaultSource, error) {
	address := strings.TrimRight(cfg.Address, "/")

	s := &VaultSource{
		client: &http.Client{
			Timeout: 10 * time.Second,
			Transport: &http.Transport{
				TLSClientConfig: &tls.Config{
					MinVersion: tls.VersionTLS12,
				},
			},
		},
		address: address,
		mount:   cfg.Mount,
		prefix:  cfg.Prefix,
	}

	switch cfg.Auth {
	case "token":
		s.authFn = func(_ context.Context) (string, time.Duration, error) {
			token := os.Getenv("VAULT_TOKEN")
			if token == "" {
				return "", 0, fmt.Errorf("VAULT_TOKEN not set")
			}
			return token, 0, nil
		}
	case "kubernetes":
		s.authFn = func(ctx context.Context) (string, time.Duration, error) {
			return s.kubernetesLogin(ctx)
		}
	default:
		return nil, fmt.Errorf("unsupported vault auth method: %q", cfg.Auth)
	}

	return s, nil
}

func (s *VaultSource) Name() string { return "vault" }

func (s *VaultSource) Resolve(ctx context.Context, name string) (string, bool, error) {
	token, err := s.getToken(ctx)
	if err != nil {
		return "", false, fmt.Errorf("vault auth: %w", err)
	}

	path, key := splitVaultName(s.prefix + name)

	url := fmt.Sprintf("%s/v1/%s/data/%s", s.address, s.mount, path)
	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return "", false, fmt.Errorf("vault request: %w", err)
	}
	req.Header.Set("X-Vault-Token", token)

	resp, err := s.client.Do(req)
	if err != nil {
		return "", false, fmt.Errorf("vault request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusNotFound {
		return "", false, nil
	}
	if resp.StatusCode != http.StatusOK {
		io.Copy(io.Discard, io.LimitReader(resp.Body, 1024))
		return "", false, fmt.Errorf("vault: unexpected status %s", resp.Status)
	}

	var result struct {
		Data struct {
			Data map[string]any `json:"data"`
		} `json:"data"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return "", false, fmt.Errorf("vault response: %w", err)
	}

	val, ok := result.Data.Data[key]
	if !ok {
		return "", false, nil
	}
	str, ok := val.(string)
	if !ok {
		return fmt.Sprintf("%v", val), true, nil
	}
	return str, true, nil
}

func (s *VaultSource) getToken(ctx context.Context) (string, error) {
	s.mu.RLock()
	if s.token != "" && (s.expiry.IsZero() || time.Now().Before(s.expiry.Add(-30*time.Second))) {
		token := s.token
		s.mu.RUnlock()
		return token, nil
	}
	s.mu.RUnlock()

	s.mu.Lock()
	defer s.mu.Unlock()

	if s.token != "" && (s.expiry.IsZero() || time.Now().Before(s.expiry.Add(-30*time.Second))) {
		return s.token, nil
	}

	token, ttl, err := s.authFn(ctx)
	if err != nil {
		return "", err
	}
	s.token = token
	if ttl > 0 {
		s.expiry = time.Now().Add(ttl)
	} else {
		s.expiry = time.Time{}
	}
	return token, nil
}

func (s *VaultSource) kubernetesLogin(ctx context.Context) (string, time.Duration, error) {
	jwt, err := os.ReadFile("/var/run/secrets/kubernetes.io/serviceaccount/token")
	if err != nil {
		return "", 0, fmt.Errorf("reading service account token: %w", err)
	}

	role := os.Getenv("VAULT_K8S_ROLE")
	if role == "" {
		role = "warden"
	}

	body := fmt.Sprintf(`{"jwt":%q,"role":%q}`, string(jwt), role)
	url := fmt.Sprintf("%s/v1/auth/kubernetes/login", s.address)
	req, err := http.NewRequestWithContext(ctx, "POST", url, strings.NewReader(body))
	if err != nil {
		return "", 0, err
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := s.client.Do(req)
	if err != nil {
		return "", 0, fmt.Errorf("vault k8s login: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		io.Copy(io.Discard, io.LimitReader(resp.Body, 1024))
		return "", 0, fmt.Errorf("vault k8s login: unexpected status %s", resp.Status)
	}

	var result struct {
		Auth struct {
			ClientToken   string `json:"client_token"`
			LeaseDuration int    `json:"lease_duration"`
		} `json:"auth"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return "", 0, fmt.Errorf("vault k8s login response: %w", err)
	}

	return result.Auth.ClientToken, time.Duration(result.Auth.LeaseDuration) * time.Second, nil
}

// splitVaultName splits "path/to/secret/key" into ("path/to/secret", "key").
// If no slash, uses name as both path and key.
func splitVaultName(name string) (string, string) {
	if i := strings.LastIndex(name, "/"); i >= 0 {
		return name[:i], name[i+1:]
	}
	return name, name
}
