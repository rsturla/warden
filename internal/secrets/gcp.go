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
			CredentialsFile: cfg.GCPServiceAccount.CredentialsFile,
			Scopes:          cfg.GCPServiceAccount.Scopes,
			TokenName:       cfg.GCPServiceAccount.TokenName,
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
	credType  string // "service_account", "authorized_user", or "metadata"

	// service_account fields
	key    *rsa.PrivateKey
	email  string
	scopes string

	// authorized_user fields
	clientID     string
	clientSecret string
	refreshTok   string

	tokenURL string
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
		s.credType = "metadata"
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
		Type         string `json:"type"`
		ClientEmail  string `json:"client_email"`
		PrivateKey   string `json:"private_key"`
		TokenURI     string `json:"token_uri"`
		ClientID     string `json:"client_id"`
		ClientSecret string `json:"client_secret"`
		RefreshToken string `json:"refresh_token"`
	}
	if err := json.Unmarshal(data, &creds); err != nil {
		return fmt.Errorf("parsing gcp credentials: %w", err)
	}

	s.tokenURL = creds.TokenURI
	if s.tokenURL == "" {
		s.tokenURL = gcpDefaultTokenURL
	}

	switch creds.Type {
	case "service_account":
		return s.loadServiceAccount(creds.ClientEmail, creds.PrivateKey, cfg.Scopes)
	case "authorized_user":
		return s.loadAuthorizedUser(creds.ClientID, creds.ClientSecret, creds.RefreshToken)
	default:
		return fmt.Errorf("unsupported gcp credentials type %q (expected service_account or authorized_user)", creds.Type)
	}
}

func (s *GCPServiceAccountSource) loadServiceAccount(email, privateKey string, scopes []string) error {
	if email == "" {
		return fmt.Errorf("gcp credentials missing client_email")
	}
	if privateKey == "" {
		return fmt.Errorf("gcp credentials missing private_key")
	}

	key, err := parseRSAPrivateKey([]byte(privateKey))
	if err != nil {
		return fmt.Errorf("parsing gcp private key: %w", err)
	}

	s.credType = "service_account"
	s.key = key
	s.email = email

	if len(scopes) == 0 {
		scopes = []string{gcpDefaultScope}
	}
	s.scopes = strings.Join(scopes, " ")

	return nil
}

func (s *GCPServiceAccountSource) loadAuthorizedUser(clientID, clientSecret, refreshToken string) error {
	if clientID == "" {
		return fmt.Errorf("gcp credentials missing client_id")
	}
	if clientSecret == "" {
		return fmt.Errorf("gcp credentials missing client_secret")
	}
	if refreshToken == "" {
		return fmt.Errorf("gcp credentials missing refresh_token")
	}

	s.credType = "authorized_user"
	s.clientID = clientID
	s.clientSecret = clientSecret
	s.refreshTok = refreshToken

	return nil
}

func (s *GCPServiceAccountSource) Name() string { return "gcp-service-account" }

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
	switch s.credType {
	case "service_account":
		return s.exchangeJWT(ctx)
	case "authorized_user":
		return s.exchangeRefreshToken(ctx)
	default:
		return s.metadataToken(ctx)
	}
}

func (s *GCPServiceAccountSource) exchangeRefreshToken(ctx context.Context) (string, time.Time, error) {
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

	return s.doTokenRequest(req)
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

	body := "grant_type=urn%3Aietf%3Aparams%3Aoauth%3Agrant-type%3Ajwt-bearer&assertion=" + jwt
	req, err := http.NewRequestWithContext(ctx, "POST", s.tokenURL, strings.NewReader(body))
	if err != nil {
		return "", time.Time{}, err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	return s.doTokenRequest(req)
}

func (s *GCPServiceAccountSource) metadataToken(ctx context.Context) (string, time.Time, error) {
	req, err := http.NewRequestWithContext(ctx, "GET", s.tokenURL, nil)
	if err != nil {
		return "", time.Time{}, err
	}
	req.Header.Set("Metadata-Flavor", "Google")

	return s.doTokenRequest(req)
}

func (s *GCPServiceAccountSource) doTokenRequest(req *http.Request) (string, time.Time, error) {
	resp, err := s.client.Do(req)
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
