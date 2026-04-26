package secrets

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strings"
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
	config.RegisterSecretValidator("vault", func(cfg config.SecretConfig) error {
		if cfg.Vault.Address == "" {
			return fmt.Errorf("secret source 'vault' requires address")
		}
		if cfg.Vault.Auth != "" && cfg.Vault.Auth != "token" && cfg.Vault.Auth != "kubernetes" {
			return fmt.Errorf("secret source 'vault': auth must be 'token' or 'kubernetes', got %q", cfg.Vault.Auth)
		}
		return nil
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
	baseURL *url.URL
	mount   string
	prefix  string
	cache   *tokenCache
	authFn  func(ctx context.Context) (string, time.Duration, error)
}

func NewVaultSource(cfg VaultConfig) (*VaultSource, error) {
	parsed, err := url.Parse(strings.TrimRight(cfg.Address, "/"))
	if err != nil {
		return nil, fmt.Errorf("invalid vault address: %w", err)
	}
	if parsed.Scheme != "http" && parsed.Scheme != "https" {
		return nil, fmt.Errorf("vault address must use http or https scheme, got %q", parsed.Scheme)
	}

	s := &VaultSource{
		client:  newSecureHTTPClient(),
		baseURL: parsed,
		mount:   cfg.Mount,
		prefix:  cfg.Prefix,
		cache:   newTokenCache(30 * time.Second),
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

	reqURL, err := url.JoinPath(s.baseURL.String(), "v1", s.mount, "data", path)
	if err != nil {
		return "", false, fmt.Errorf("vault URL: %w", err)
	}
	req, err := http.NewRequestWithContext(ctx, "GET", reqURL, nil)
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
		_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 1024))
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
	return s.cache.GetOrRefresh(ctx, func(ctx context.Context) (string, time.Time, error) {
		token, ttl, err := s.authFn(ctx)
		if err != nil {
			return "", time.Time{}, err
		}
		var expiry time.Time
		if ttl > 0 {
			expiry = time.Now().Add(ttl)
		}
		return token, expiry, nil
	})
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
	loginURL, err := url.JoinPath(s.baseURL.String(), "v1", "auth", "kubernetes", "login")
	if err != nil {
		return "", 0, fmt.Errorf("vault login URL: %w", err)
	}
	req, err := http.NewRequestWithContext(ctx, "POST", loginURL, strings.NewReader(body))
	if err != nil {
		return "", 0, err
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := s.client.Do(req) // #nosec G704 -- URL constructed from admin-configured vault address validated at init
	if err != nil {
		return "", 0, fmt.Errorf("vault k8s login: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 1024))
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
