package secrets

import (
	"context"
	"crypto/rsa"
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

const gcpDefaultTokenURL = "https://oauth2.googleapis.com/token"
const gcpMetadataTokenURL = "http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token"
const gcpDefaultScope = "https://www.googleapis.com/auth/cloud-platform"

func init() {
	Register("gcp-service-account", func(cfg config.SecretConfig) (SecretSource, error) {
		return NewGCPServiceAccountSource(GCPServiceAccountConfig{
			CredentialsFile: cfg.GCP.CredentialsFile,
			Scopes:          cfg.GCP.Scopes,
			TokenName:       cfg.GCP.TokenName,
		})
	})
	config.RegisterSecretValidator("gcp-service-account", nil)
}

type GCPServiceAccountConfig struct {
	CredentialsFile string
	Scopes          []string
	TokenName       string // variable name to respond to (default: GCP_ACCESS_TOKEN)
	TokenURL        string // override for testing
}

type GCPServiceAccountSource struct {
	client    *http.Client
	cache     *tokenCache
	tokenName string
	key       *rsa.PrivateKey // nil = metadata mode
	email     string
	scopes    string
	tokenURL  string
}

func NewGCPServiceAccountSource(cfg GCPServiceAccountConfig) (*GCPServiceAccountSource, error) {
	tokenName := cfg.TokenName
	if tokenName == "" {
		tokenName = "GCP_ACCESS_TOKEN"
	}

	s := &GCPServiceAccountSource{
		client:    newSecureHTTPClient(),
		cache:     newTokenCache(5 * time.Minute),
		tokenName: tokenName,
	}

	if cfg.CredentialsFile != "" {
		if err := s.loadCredentials(cfg); err != nil {
			return nil, err
		}
	} else {
		s.tokenURL = gcpMetadataTokenURL
	}

	if cfg.TokenURL != "" {
		s.tokenURL = cfg.TokenURL
	}

	return s, nil
}

func (s *GCPServiceAccountSource) loadCredentials(cfg GCPServiceAccountConfig) error {
	data, err := os.ReadFile(cfg.CredentialsFile)
	if err != nil {
		return fmt.Errorf("reading gcp credentials: %w", err)
	}

	var creds struct {
		Type        string `json:"type"`
		ClientEmail string `json:"client_email"`
		PrivateKey  string `json:"private_key"`
		TokenURI    string `json:"token_uri"`
	}
	if err := json.Unmarshal(data, &creds); err != nil {
		return fmt.Errorf("parsing gcp credentials: %w", err)
	}

	if creds.Type != "service_account" {
		return fmt.Errorf("gcp credentials type must be 'service_account', got %q", creds.Type)
	}
	if creds.ClientEmail == "" {
		return fmt.Errorf("gcp credentials missing client_email")
	}
	if creds.PrivateKey == "" {
		return fmt.Errorf("gcp credentials missing private_key")
	}

	key, err := parseRSAPrivateKey([]byte(creds.PrivateKey))
	if err != nil {
		return fmt.Errorf("parsing gcp private key: %w", err)
	}

	s.key = key
	s.email = creds.ClientEmail

	scopes := cfg.Scopes
	if len(scopes) == 0 {
		scopes = []string{gcpDefaultScope}
	}
	s.scopes = strings.Join(scopes, " ")

	s.tokenURL = creds.TokenURI
	if s.tokenURL == "" {
		s.tokenURL = gcpDefaultTokenURL
	}

	return nil
}

func (s *GCPServiceAccountSource) Name() string            { return "gcp-service-account" }
func (s *GCPServiceAccountSource) TokenTTL() time.Duration { return s.cache.TTL() }

func (s *GCPServiceAccountSource) Resolve(ctx context.Context, name string) (string, bool, error) {
	if name != s.tokenName {
		return "", false, nil
	}

	token, err := s.cache.GetOrRefresh(ctx, s.refreshToken)
	if err != nil {
		return "", false, fmt.Errorf("gcp token: %w", err)
	}
	return token, true, nil
}

func (s *GCPServiceAccountSource) refreshToken(ctx context.Context) (string, time.Time, error) {
	if s.key == nil {
		return s.metadataToken(ctx)
	}
	return s.exchangeJWT(ctx)
}

func (s *GCPServiceAccountSource) exchangeJWT(ctx context.Context) (string, time.Time, error) {
	now := time.Now()
	jwt, err := signRS256JWT(s.key, map[string]any{
		"iss":   s.email,
		"scope": s.scopes,
		"aud":   s.tokenURL,
		"iat":   now.Unix(),
		"exp":   now.Add(1 * time.Hour).Unix(),
	})
	if err != nil {
		return "", time.Time{}, fmt.Errorf("creating JWT: %w", err)
	}

	body := url.Values{
		"grant_type": {"urn:ietf:params:oauth:grant-type:jwt-bearer"},
		"assertion":  {jwt},
	}.Encode()
	req, err := http.NewRequestWithContext(ctx, "POST", s.tokenURL, strings.NewReader(body))
	if err != nil {
		return "", time.Time{}, err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	return doGCPTokenRequest(s.client, req)
}

func (s *GCPServiceAccountSource) metadataToken(ctx context.Context) (string, time.Time, error) {
	req, err := http.NewRequestWithContext(ctx, "GET", s.tokenURL, nil)
	if err != nil {
		return "", time.Time{}, err
	}
	req.Header.Set("Metadata-Flavor", "Google")

	return doGCPTokenRequest(s.client, req)
}

func doGCPTokenRequest(client *http.Client, req *http.Request) (string, time.Time, error) {
	resp, err := client.Do(req)
	if err != nil {
		return "", time.Time{}, fmt.Errorf("gcp token request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 1024))
		return "", time.Time{}, fmt.Errorf("gcp token request: unexpected status %s", resp.Status)
	}

	var result struct {
		AccessToken string `json:"access_token"`
		ExpiresIn   int    `json:"expires_in"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return "", time.Time{}, fmt.Errorf("gcp token response: %w", err)
	}

	if result.AccessToken == "" {
		return "", time.Time{}, fmt.Errorf("gcp token response: empty access_token")
	}

	expiry := time.Now().Add(time.Duration(result.ExpiresIn) * time.Second)
	return result.AccessToken, expiry, nil
}
