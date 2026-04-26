package controller

import (
	"testing"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/resource"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"github.com/rsturla/warden/internal/config"
	wardenio "github.com/rsturla/warden/operator/api/v1alpha1"
	"go.yaml.in/yaml/v3"
)

func TestBuildWardenConfig_SingleTenant(t *testing.T) {
	proxy := &wardenio.WardenProxy{
		ObjectMeta: metav1.ObjectMeta{Name: "warden", Namespace: "default"},
		Spec: wardenio.WardenProxySpec{
			Image: "warden:latest",
			DNS: &wardenio.DNSSpec{
				Cache:           &wardenio.CacheSpec{Enabled: true, MaxTTL: 600},
				DenyResolvedIPs: []string{"169.254.0.0/16"},
			},
			Telemetry: &wardenio.TelemetrySpec{
				Logs: &wardenio.LogsSpec{Level: "info", Format: "json"},
			},
		},
	}

	cfg := buildWardenConfig(proxy)

	if cfg.Server.Listen != "0.0.0.0:8080" {
		t.Errorf("listen = %q, want 0.0.0.0:8080", cfg.Server.Listen)
	}
	if cfg.Server.TLS != nil {
		t.Error("TLS should be nil for single-tenant")
	}
	if !cfg.CA.Auto {
		t.Error("CA auto should be true for single-tenant")
	}
	if cfg.Tenants != nil {
		t.Error("tenants should be nil for single-tenant")
	}
	if cfg.DNS == nil || !cfg.DNS.Cache.Enabled {
		t.Error("DNS cache not enabled")
	}
	if cfg.DNS.Cache.MaxTTL != 600 {
		t.Errorf("max TTL = %d, want 600", cfg.DNS.Cache.MaxTTL)
	}
}

func TestBuildWardenConfig_MultiTenant(t *testing.T) {
	proxy := &wardenio.WardenProxy{
		ObjectMeta: metav1.ObjectMeta{Name: "warden-mt"},
		Spec: wardenio.WardenProxySpec{
			Image: "warden:latest",
			MultiTenant: &wardenio.MultiTenantSpec{
				CertificateIssuerRef: wardenio.IssuerReference{Name: "ca-issuer", Kind: "Issuer"},
			},
		},
	}

	cfg := buildWardenConfig(proxy)

	if cfg.Server.Listen != "0.0.0.0:8443" {
		t.Errorf("listen = %q, want 0.0.0.0:8443", cfg.Server.Listen)
	}
	if cfg.Server.TLS == nil {
		t.Fatal("TLS should be set for multi-tenant")
	}
	if cfg.Server.TLS.Cert != "/etc/warden/tls/tls.crt" {
		t.Errorf("cert = %q", cfg.Server.TLS.Cert)
	}
	if cfg.Server.TLS.ClientCA != "/etc/warden/tenant-ca/ca.crt" {
		t.Errorf("client_ca = %q", cfg.Server.TLS.ClientCA)
	}
	if cfg.Tenants == nil || cfg.Tenants.Dir != "/etc/warden/tenants.d/" {
		t.Errorf("tenants = %+v", cfg.Tenants)
	}
	if cfg.CA.Cert != "/etc/warden/mitm/ca.crt" {
		t.Errorf("ca cert = %q", cfg.CA.Cert)
	}
}

func TestBuildWardenConfig_ParseableByProxy(t *testing.T) {
	proxy := &wardenio.WardenProxy{
		ObjectMeta: metav1.ObjectMeta{Name: "test"},
		Spec: wardenio.WardenProxySpec{
			Image: "warden:latest",
			DNS: &wardenio.DNSSpec{
				Cache:           &wardenio.CacheSpec{Enabled: true},
				DenyResolvedIPs: []string{"169.254.0.0/16", "10.0.0.0/8"},
			},
			Telemetry: &wardenio.TelemetrySpec{
				Logs: &wardenio.LogsSpec{Level: "debug", Format: "json"},
			},
		},
	}

	cfg := buildWardenConfig(proxy)
	data, err := yaml.Marshal(cfg)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}

	_, err = config.Parse(data)
	if err != nil {
		t.Fatalf("proxy config.Parse failed: %v\nYAML:\n%s", err, string(data))
	}
}

func TestProxyPort(t *testing.T) {
	tests := []struct {
		name string
		mt   bool
		want int32
	}{
		{"single-tenant", false, 8080},
		{"multi-tenant", true, 8443},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			proxy := &wardenio.WardenProxy{Spec: wardenio.WardenProxySpec{}}
			if tt.mt {
				proxy.Spec.MultiTenant = &wardenio.MultiTenantSpec{}
			}
			if got := proxyPort(proxy); got != tt.want {
				t.Errorf("proxyPort = %d, want %d", got, tt.want)
			}
		})
	}
}

func TestConfigMapName(t *testing.T) {
	proxy := &wardenio.WardenProxy{ObjectMeta: metav1.ObjectMeta{Name: "prod"}}
	if got := configMapName(proxy); got != "prod-tenants" {
		t.Errorf("configMapName = %q, want prod-tenants", got)
	}
}

func TestBuildWardenConfig_Telemetry(t *testing.T) {
	proxy := &wardenio.WardenProxy{
		ObjectMeta: metav1.ObjectMeta{Name: "test"},
		Spec: wardenio.WardenProxySpec{
			Image: "warden:latest",
			Telemetry: &wardenio.TelemetrySpec{
				Logs:    &wardenio.LogsSpec{Level: "warn", Format: "text"},
				Traces:  &wardenio.TracesSpec{Enabled: true, Endpoint: "http://otel:4318"},
				Metrics: &wardenio.MetricsSpec{Enabled: true, Endpoint: "http://otel:4318"},
			},
		},
	}

	cfg := buildWardenConfig(proxy)

	if cfg.Telemetry == nil {
		t.Fatal("telemetry is nil")
	}
	if cfg.Telemetry.Logs.Level != "warn" {
		t.Errorf("logs level = %q", cfg.Telemetry.Logs.Level)
	}
	if !cfg.Telemetry.Traces.Enabled || cfg.Telemetry.Traces.Endpoint != "http://otel:4318" {
		t.Errorf("traces = %+v", cfg.Telemetry.Traces)
	}
	if !cfg.Telemetry.Metrics.Enabled {
		t.Error("metrics not enabled")
	}
}

func TestBuildWardenConfig_Replicas(t *testing.T) {
	replicas := int32(3)
	proxy := &wardenio.WardenProxy{
		Spec: wardenio.WardenProxySpec{
			Image:    "warden:latest",
			Replicas: &replicas,
			Resources: corev1.ResourceRequirements{
				Requests: corev1.ResourceList{
					corev1.ResourceCPU:    resource.MustParse("200m"),
					corev1.ResourceMemory: resource.MustParse("128Mi"),
				},
			},
		},
	}

	if *proxy.Spec.Replicas != 3 {
		t.Errorf("replicas = %d, want 3", *proxy.Spec.Replicas)
	}

	cpu := proxy.Spec.Resources.Requests[corev1.ResourceCPU]
	if cpu.String() != "200m" {
		t.Errorf("cpu = %s, want 200m", cpu.String())
	}
}

func TestCertSecretName(t *testing.T) {
	if got := certSecretName("alpha"); got != "warden-tenant-alpha-cert" {
		t.Errorf("certSecretName = %q", got)
	}
}
