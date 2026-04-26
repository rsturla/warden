package secrets

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/rsturla/warden/internal/config"
)

func init() {
	Register("kubernetes", func(cfg config.SecretConfig) (SecretSource, error) {
		return NewKubernetesSource(K8sConfig{
			Namespace: cfg.Kubernetes.Namespace,
		})
	})
	config.RegisterSecretValidator("kubernetes", nil)
}

const (
	k8sTokenPath     = "/var/run/secrets/kubernetes.io/serviceaccount/token" // #nosec G101 -- standard k8s mount path, not credentials
	k8sCACertPath    = "/var/run/secrets/kubernetes.io/serviceaccount/ca.crt"
	k8sNamespacePath = "/var/run/secrets/kubernetes.io/serviceaccount/namespace"
)

type K8sConfig struct {
	Namespace string
}

type KubernetesSource struct {
	client    *http.Client
	apiServer string
	namespace string
}

func NewKubernetesSource(cfg K8sConfig) (*KubernetesSource, error) {
	host := os.Getenv("KUBERNETES_SERVICE_HOST")
	port := os.Getenv("KUBERNETES_SERVICE_PORT")
	if host == "" {
		host = "kubernetes.default.svc"
	}
	if port == "" {
		port = "443"
	}

	apiServer := "https://" + net.JoinHostPort(host, port)

	ns := cfg.Namespace
	if ns == "" {
		data, err := os.ReadFile(k8sNamespacePath)
		if err != nil {
			ns = "default"
		} else {
			ns = strings.TrimSpace(string(data))
		}
	}

	client, err := buildK8sClient()
	if err != nil {
		return nil, fmt.Errorf("kubernetes client: %w", err)
	}

	return &KubernetesSource{
		client:    client,
		apiServer: apiServer,
		namespace: ns,
	}, nil
}

func (s *KubernetesSource) Name() string { return "kubernetes" }

func (s *KubernetesSource) Resolve(ctx context.Context, name string) (string, bool, error) {
	secretName, key := splitK8sName(name)

	token, err := os.ReadFile(k8sTokenPath)
	if err != nil {
		return "", false, fmt.Errorf("reading k8s token: %w", err)
	}

	url := fmt.Sprintf("%s/api/v1/namespaces/%s/secrets/%s", s.apiServer, s.namespace, secretName)
	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return "", false, fmt.Errorf("k8s request: %w", err)
	}
	req.Header.Set("Authorization", "Bearer "+strings.TrimSpace(string(token)))

	resp, err := s.client.Do(req)
	if err != nil {
		return "", false, fmt.Errorf("k8s request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusNotFound {
		return "", false, nil
	}
	if resp.StatusCode != http.StatusOK {
		_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 1024))
		return "", false, fmt.Errorf("k8s: unexpected status %s", resp.Status)
	}

	var result struct {
		Data map[string]string `json:"data"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return "", false, fmt.Errorf("k8s response: %w", err)
	}

	encoded, ok := result.Data[key]
	if !ok {
		return "", false, nil
	}

	decoded, err := base64.StdEncoding.DecodeString(encoded)
	if err != nil {
		return encoded, true, nil
	}
	return string(decoded), true, nil
}

// splitK8sName splits "secretname/key" into (secret, key).
// If no slash, uses name as both secret name and key.
func splitK8sName(name string) (string, string) {
	if i := strings.Index(name, "/"); i >= 0 {
		return name[:i], name[i+1:]
	}
	return name, name
}

func buildK8sClient() (*http.Client, error) {
	caCert, err := os.ReadFile(k8sCACertPath)
	if err != nil {
		return nil, fmt.Errorf("reading k8s CA cert %s: %w", k8sCACertPath, err)
	}

	pool := x509.NewCertPool()
	pool.AppendCertsFromPEM(caCert)

	return &http.Client{
		Timeout: 10 * time.Second,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{
				RootCAs:    pool,
				MinVersion: tls.VersionTLS12,
			},
		},
	}, nil
}
