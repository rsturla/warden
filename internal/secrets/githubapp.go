package secrets

import (
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
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
	Register("github-app", func(cfg config.SecretConfig) (SecretSource, error) {
		return NewGitHubAppSource(GitHubAppConfig{
			AppID:          cfg.GitHubApp.AppID,
			InstallationID: cfg.GitHubApp.InstallationID,
			PrivateKeyPath: cfg.GitHubApp.PrivateKeyPath,
		})
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

	mu     sync.RWMutex
	token  string
	expiry time.Time
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
		client: &http.Client{
			Timeout: 10 * time.Second,
			Transport: &http.Transport{
				TLSClientConfig: &tls.Config{
					MinVersion: tls.VersionTLS12,
				},
			},
		},
		apiBase: strings.TrimRight(apiBase, "/"),
	}, nil
}

func (s *GitHubAppSource) Name() string { return "github-app" }

func (s *GitHubAppSource) Resolve(ctx context.Context, name string) (string, bool, error) {
	if name != "GITHUB_TOKEN" {
		return "", false, nil
	}

	token, err := s.getInstallationToken(ctx)
	if err != nil {
		return "", false, fmt.Errorf("github app token: %w", err)
	}
	return token, true, nil
}

func (s *GitHubAppSource) getInstallationToken(ctx context.Context) (string, error) {
	s.mu.RLock()
	if s.token != "" && time.Now().Before(s.expiry.Add(-5*time.Minute)) {
		token := s.token
		s.mu.RUnlock()
		return token, nil
	}
	s.mu.RUnlock()

	s.mu.Lock()
	defer s.mu.Unlock()

	if s.token != "" && time.Now().Before(s.expiry.Add(-5*time.Minute)) {
		return s.token, nil
	}

	jwt, err := s.createJWT()
	if err != nil {
		return "", fmt.Errorf("creating JWT: %w", err)
	}

	url := fmt.Sprintf("%s/app/installations/%d/access_tokens", s.apiBase, s.installationID)
	req, err := http.NewRequestWithContext(ctx, "POST", url, nil)
	if err != nil {
		return "", err
	}
	req.Header.Set("Authorization", "Bearer "+jwt)
	req.Header.Set("Accept", "application/vnd.github+json")

	resp, err := s.client.Do(req)
	if err != nil {
		return "", fmt.Errorf("token exchange: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusCreated {
		io.Copy(io.Discard, io.LimitReader(resp.Body, 1024))
		return "", fmt.Errorf("token exchange: unexpected status %s", resp.Status)
	}

	var result struct {
		Token     string `json:"token"`
		ExpiresAt string `json:"expires_at"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return "", fmt.Errorf("token response: %w", err)
	}

	expiry, err := time.Parse(time.RFC3339, result.ExpiresAt)
	if err != nil {
		expiry = time.Now().Add(1 * time.Hour)
	}

	s.token = result.Token
	s.expiry = expiry
	return s.token, nil
}

func (s *GitHubAppSource) createJWT() (string, error) {
	now := time.Now()
	header := base64URLEncode([]byte(`{"alg":"RS256","typ":"JWT"}`))

	claims, err := json.Marshal(map[string]any{
		"iss": s.appID,
		"iat": now.Add(-60 * time.Second).Unix(),
		"exp": now.Add(10 * time.Minute).Unix(),
	})
	if err != nil {
		return "", err
	}
	payload := base64URLEncode(claims)

	signingInput := header + "." + payload
	hash := sha256.Sum256([]byte(signingInput))
	sig, err := rsa.SignPKCS1v15(rand.Reader, s.key, crypto.SHA256, hash[:])
	if err != nil {
		return "", err
	}

	return signingInput + "." + base64URLEncode(sig), nil
}

func base64URLEncode(data []byte) string {
	return base64.RawURLEncoding.EncodeToString(data)
}

func parseRSAPrivateKey(data []byte) (*rsa.PrivateKey, error) {
	block, _ := pem.Decode(data)
	if block == nil {
		return nil, fmt.Errorf("no PEM block found")
	}

	key, err := x509.ParsePKCS1PrivateKey(block.Bytes)
	if err != nil {
		parsed, err2 := x509.ParsePKCS8PrivateKey(block.Bytes)
		if err2 != nil {
			return nil, fmt.Errorf("parsing key: %w (pkcs1: %v)", err2, err)
		}
		rsaKey, ok := parsed.(*rsa.PrivateKey)
		if !ok {
			return nil, fmt.Errorf("key is not RSA")
		}
		return rsaKey, nil
	}
	return key, nil
}
