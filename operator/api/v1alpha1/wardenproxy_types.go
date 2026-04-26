package v1alpha1

import (
	"github.com/rsturla/warden/pkg/api"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// +kubebuilder:object:root=true
// +kubebuilder:subresource:status
// +kubebuilder:printcolumn:name="Ready",type="boolean",JSONPath=".status.ready"
// +kubebuilder:printcolumn:name="Endpoint",type="string",JSONPath=".status.endpoint"
// +kubebuilder:printcolumn:name="Tenants",type="integer",JSONPath=".status.tenantCount"
// +kubebuilder:printcolumn:name="Age",type="date",JSONPath=".metadata.creationTimestamp"

// WardenProxy is the Schema for the wardenproxies API.
type WardenProxy struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	Spec   WardenProxySpec   `json:"spec,omitempty"`
	Status WardenProxyStatus `json:"status,omitempty"`
}

type WardenProxySpec struct {
	// Image is the Warden container image (contains both warden and warden-bridge binaries)
	Image string `json:"image"`
	// Replicas for the proxy Deployment
	// +optional
	// +kubebuilder:default=1
	Replicas *int32 `json:"replicas,omitempty"`
	// Resources for the proxy container
	// +optional
	Resources corev1.ResourceRequirements `json:"resources,omitempty"`
	// DNS configuration
	// +optional
	DNS *DNSSpec `json:"dns,omitempty"`
	// MultiTenant enables multi-tenant mode with mTLS
	// +optional
	MultiTenant *MultiTenantSpec `json:"multiTenant,omitempty"`
	// Telemetry configuration
	// +optional
	Telemetry *TelemetrySpec `json:"telemetry,omitempty"`
	// ExtraVolumes are additional volumes to mount on the proxy pod.
	// Use this to provide credential files referenced by tenant secret backends.
	// +optional
	ExtraVolumes []corev1.Volume `json:"extraVolumes,omitempty"`
	// ExtraVolumeMounts are additional volume mounts for the proxy container.
	// +optional
	ExtraVolumeMounts []corev1.VolumeMount `json:"extraVolumeMounts,omitempty"`
	// Policies for single-tenant mode (mutually exclusive with MultiTenant)
	// +optional
	Policies []api.PolicyRule `json:"policies,omitempty"`
	// Secrets for single-tenant mode (mutually exclusive with MultiTenant)
	// +optional
	Secrets []api.SecretConfig `json:"secrets,omitempty"`
}

type DNSSpec struct {
	Cache           *CacheSpec `json:"cache,omitempty"`
	DenyResolvedIPs []string   `json:"denyResolvedIPs,omitempty"`
}

type CacheSpec struct {
	Enabled bool `json:"enabled,omitempty"`
	MaxTTL  int  `json:"maxTTL,omitempty"`
}

type MultiTenantSpec struct {
	CertificateIssuerRef IssuerReference `json:"certificateIssuerRef"`
	// BridgeResources for injected warden-bridge sidecars
	// +optional
	BridgeResources corev1.ResourceRequirements `json:"bridgeResources,omitempty"`
}

type IssuerReference struct {
	Name string `json:"name"`
	// +kubebuilder:default=Issuer
	Kind string `json:"kind,omitempty"`
}

type TelemetrySpec struct {
	Logs    *LogsSpec    `json:"logs,omitempty"`
	Traces  *TracesSpec  `json:"traces,omitempty"`
	Metrics *MetricsSpec `json:"metrics,omitempty"`
}

type LogsSpec struct {
	// +kubebuilder:default=info
	Level string `json:"level,omitempty"`
	// +kubebuilder:default=json
	Format string `json:"format,omitempty"`
}

type TracesSpec struct {
	Enabled  bool   `json:"enabled,omitempty"`
	Endpoint string `json:"endpoint,omitempty"`
}

type MetricsSpec struct {
	Enabled  bool   `json:"enabled,omitempty"`
	Endpoint string `json:"endpoint,omitempty"`
}

type WardenProxyStatus struct {
	Ready              bool               `json:"ready,omitempty"`
	Endpoint           string             `json:"endpoint,omitempty"`
	TenantCount        int                `json:"tenantCount,omitempty"`
	ObservedGeneration int64              `json:"observedGeneration,omitempty"`
	Conditions         []metav1.Condition `json:"conditions,omitempty"`
}

// +kubebuilder:object:root=true

// WardenProxyList contains a list of WardenProxy.
type WardenProxyList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []WardenProxy `json:"items"`
}

func init() {
	SchemeBuilder.Register(&WardenProxy{}, &WardenProxyList{})
}
