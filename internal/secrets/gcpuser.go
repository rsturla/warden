package secrets

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/rsturla/warden/internal/config"
)

func init() {
	Register("gcp-authorized-user", func(cfg config.SecretConfig) (SecretSource, error) {
		return NewGCPAuthorizedUserSource(GCPAuthorizedUserConfig{
			CredentialsFile: cfg.GCP.CredentialsFile,
			TokenName:       cfg.GCP.TokenName,
		})
	})
	config.RegisterSecretValidator("gcp-authorized-user", func(cfg config.SecretConfig) error {
		if cfg.GCP.CredentialsFile == "" {
			return fmt.Errorf("secret source 'gcp-authorized-user' requires credentials_file")
		}
		return nil
	})
}

type GCPAuthorizedUserConfig struct {
	CredentialsFile string
	TokenName       string // variable name to respond to (default: GCP_ACCESS_TOKEN)
	TokenURL        string // override for testing
}

type GCPAuthorizedUserSource struct {
	client       *http.Client
	cache        *tokenCache
	tokenName    string
	clientID     string
	clientSecret string
	refreshTok   string
	tokenURL     string
}

func NewGCPAuthorizedUserSource(cfg GCPAuthorizedUserConfig) (*GCPAuthorizedUserSource, error) {
	tokenName := cfg.TokenName
	if tokenName == "" {
		tokenName = "GCP_ACCESS_TOKEN"
	}

	s := &GCPAuthorizedUserSource{
		client:    newSecureHTTPClient(),
		cache:     newTokenCache(5 * time.Minute),
		tokenName: tokenName,
		tokenURL:  gcpDefaultTokenURL,
	}

	if cfg.CredentialsFile != "" {
		if err := s.loadCredentials(cfg.CredentialsFile); err != nil {
			return nil, err
		}
	}

	if cfg.TokenURL != "" {
		s.tokenURL = cfg.TokenURL
	}

	if s.clientID == "" || s.clientSecret == "" || s.refreshTok == "" {
		return nil, fmt.Errorf("gcp-authorized-user: credentials_file is required")
	}

	return s, nil
}

func (s *GCPAuthorizedUserSource) loadCredentials(path string) error {
	data, err := os.ReadFile(path) // #nosec G304 -- path is admin-configured credentials_file from trusted config
	if err != nil {
		return fmt.Errorf("reading gcp credentials: %w", err)
	}

	var creds struct {
		Type         string `json:"type"`
		ClientID     string `json:"client_id"`
		ClientSecret string `json:"client_secret"`
		RefreshToken string `json:"refresh_token"`
		TokenURI     string `json:"token_uri"`
	}
	if err := json.Unmarshal(data, &creds); err != nil {
		return fmt.Errorf("parsing gcp credentials: %w", err)
	}

	if creds.Type != "authorized_user" {
		return fmt.Errorf("gcp credentials type must be 'authorized_user', got %q", creds.Type)
	}
	if creds.ClientID == "" {
		return fmt.Errorf("gcp credentials missing client_id")
	}
	if creds.ClientSecret == "" {
		return fmt.Errorf("gcp credentials missing client_secret")
	}
	if creds.RefreshToken == "" {
		return fmt.Errorf("gcp credentials missing refresh_token")
	}

	s.clientID = creds.ClientID
	s.clientSecret = creds.ClientSecret
	s.refreshTok = creds.RefreshToken

	if creds.TokenURI != "" {
		s.tokenURL = creds.TokenURI
	}

	return nil
}

func (s *GCPAuthorizedUserSource) Name() string            { return "gcp-authorized-user" }
func (s *GCPAuthorizedUserSource) TokenTTL() time.Duration { return s.cache.TTL() }

func (s *GCPAuthorizedUserSource) Resolve(ctx context.Context, name string) (string, bool, error) {
	if name != s.tokenName {
		return "", false, nil
	}

	token, err := s.cache.GetOrRefresh(ctx, s.exchangeRefreshToken)
	if err != nil {
		return "", false, fmt.Errorf("gcp user token: %w", err)
	}
	return token, true, nil
}

func (s *GCPAuthorizedUserSource) exchangeRefreshToken(ctx context.Context) (string, time.Time, error) {
	body := url.Values{
		"grant_type":    {"refresh_token"},
		"client_id":     {s.clientID},
		"client_secret": {s.clientSecret},
		"refresh_token": {s.refreshTok},
	}.Encode()

	req, err := http.NewRequestWithContext(ctx, "POST", s.tokenURL, strings.NewReader(body))
	if err != nil {
		return "", time.Time{}, err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	return doGCPTokenRequest(s.client, req)
}
