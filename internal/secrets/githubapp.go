package secrets

import (
	"context"
	"crypto/rsa"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/rsturla/warden/internal/config"
)

func init() {
	Register("github-app", func(cfg config.SecretConfig) (SecretSource, error) {
		return NewGitHubAppSource(GitHubAppConfig{
			AppID:          cfg.GitHubApp.AppID,
			InstallationID: cfg.GitHubApp.InstallationID,
			PrivateKeyPath: cfg.GitHubApp.PrivateKeyPath,
		})
	})
	config.RegisterSecretValidator("github-app", func(cfg config.SecretConfig) error {
		if cfg.GitHubApp.AppID <= 0 {
			return fmt.Errorf("secret source 'github-app' requires positive app_id")
		}
		if cfg.GitHubApp.InstallationID <= 0 {
			return fmt.Errorf("secret source 'github-app' requires positive installation_id")
		}
		if cfg.GitHubApp.PrivateKeyPath == "" {
			return fmt.Errorf("secret source 'github-app' requires private_key_path")
		}
		return nil
	})
}

type GitHubAppConfig struct {
	AppID          int64
	InstallationID int64
	PrivateKeyPath string
	APIBase        string // defaults to "https://api.github.com"
}

type GitHubAppSource struct {
	appID          int64
	installationID int64
	key            *rsa.PrivateKey
	client         *http.Client
	apiBase        string
	cache          *tokenCache
}

func NewGitHubAppSource(cfg GitHubAppConfig) (*GitHubAppSource, error) {
	keyData, err := os.ReadFile(cfg.PrivateKeyPath)
	if err != nil {
		return nil, fmt.Errorf("reading github app key: %w", err)
	}

	key, err := parseRSAPrivateKey(keyData)
	if err != nil {
		return nil, fmt.Errorf("parsing github app key: %w", err)
	}

	apiBase := cfg.APIBase
	if apiBase == "" {
		apiBase = "https://api.github.com"
	}

	return &GitHubAppSource{
		appID:          cfg.AppID,
		installationID: cfg.InstallationID,
		key:            key,
		client:         newSecureHTTPClient(),
		apiBase:        strings.TrimRight(apiBase, "/"),
		cache:          newTokenCache(5 * time.Minute),
	}, nil
}

func (s *GitHubAppSource) Name() string { return "github-app" }

func (s *GitHubAppSource) Resolve(ctx context.Context, name string) (string, bool, error) {
	if name != "GITHUB_TOKEN" {
		return "", false, nil
	}

	token, err := s.cache.GetOrRefresh(ctx, s.exchangeToken)
	if err != nil {
		return "", false, fmt.Errorf("github app token: %w", err)
	}
	return token, true, nil
}

func (s *GitHubAppSource) exchangeToken(ctx context.Context) (string, time.Time, error) {
	jwt, err := s.createJWT()
	if err != nil {
		return "", time.Time{}, fmt.Errorf("creating JWT: %w", err)
	}

	url := fmt.Sprintf("%s/app/installations/%d/access_tokens", s.apiBase, s.installationID)
	req, err := http.NewRequestWithContext(ctx, "POST", url, nil)
	if err != nil {
		return "", time.Time{}, err
	}
	req.Header.Set("Authorization", "Bearer "+jwt)
	req.Header.Set("Accept", "application/vnd.github+json")

	resp, err := s.client.Do(req)
	if err != nil {
		return "", time.Time{}, fmt.Errorf("token exchange: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusCreated {
		_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 1024))
		return "", time.Time{}, fmt.Errorf("token exchange: unexpected status %s", resp.Status)
	}

	var result struct {
		Token     string `json:"token"`
		ExpiresAt string `json:"expires_at"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return "", time.Time{}, fmt.Errorf("token response: %w", err)
	}

	expiry, err := time.Parse(time.RFC3339, result.ExpiresAt)
	if err != nil {
		expiry = time.Now().Add(1 * time.Hour)
	}

	return result.Token, expiry, nil
}

func (s *GitHubAppSource) createJWT() (string, error) {
	now := time.Now()
	return signRS256JWT(s.key, map[string]any{
		"iss": s.appID,
		"iat": now.Add(-60 * time.Second).Unix(),
		"exp": now.Add(10 * time.Minute).Unix(),
	})
}
