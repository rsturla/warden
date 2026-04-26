package v1alpha1

import (
	"github.com/rsturla/warden/pkg/api"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// +kubebuilder:object:root=true
// +kubebuilder:subresource:status
// +kubebuilder:printcolumn:name="Ready",type="boolean",JSONPath=".status.ready"
// +kubebuilder:printcolumn:name="Age",type="date",JSONPath=".metadata.creationTimestamp"

// Tenant is the Schema for the tenants API.
type Tenant struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	Spec   TenantSpec   `json:"spec,omitempty"`
	Status TenantStatus `json:"status,omitempty"`
}

type TenantSpec struct {
	Policies []api.PolicyRule   `json:"policies"`
	Secrets  []api.SecretConfig `json:"secrets,omitempty"`
	// CertificateSecretName references a pre-existing K8s TLS Secret for mTLS client cert.
	// When set, the operator skips cert-manager Certificate creation and uses this Secret.
	// The Secret must contain tls.crt, tls.key, and ca.crt. The cert CN must match the tenant name.
	// +optional
	CertificateSecretName string `json:"certificateSecretName,omitempty"`
}

type TenantStatus struct {
	Ready                 bool               `json:"ready,omitempty"`
	CertificateSecretName string             `json:"certificateSecretName,omitempty"`
	ConfigMapName         string             `json:"configMapName,omitempty"`
	ObservedGeneration    int64              `json:"observedGeneration,omitempty"`
	Conditions            []metav1.Condition `json:"conditions,omitempty"`
}

// +kubebuilder:object:root=true

// TenantList contains a list of Tenant.
type TenantList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []Tenant `json:"items"`
}

func init() {
	SchemeBuilder.Register(&Tenant{}, &TenantList{})
}
