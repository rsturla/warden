package webhook

import (
	"context"
	"encoding/json"
	"testing"

	admissionv1 "k8s.io/api/admission/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
	"sigs.k8s.io/controller-runtime/pkg/webhook/admission"

	wardenio "github.com/rsturla/warden/operator/api/v1alpha1"
)

func FuzzSplitJSONPointer(f *testing.F) {
	f.Add("")
	f.Add("/")
	f.Add("/spec/containers/0")
	f.Add("/metadata/labels/app")
	f.Add("no-leading-slash")
	f.Add("/a/b/c/d/e")
	f.Add("/0/1/2")

	f.Fuzz(func(t *testing.T, path string) {
		// Must not panic on any input.
		splitJSONPointer(path)
	})
}

func FuzzPodMutatorHandle(f *testing.F) {
	f.Add("app", "test:latest", "alpha")
	f.Add("nginx", "nginx:1.25", "beta")
	f.Add("my-app", "registry.example.com/img:v1.0", "tenant-1")
	f.Add("a", "b:c", "t")

	f.Fuzz(func(t *testing.T, containerName, image, tenantName string) {
		if containerName == "" || image == "" || tenantName == "" {
			return
		}

		scheme := runtime.NewScheme()
		wardenio.AddToScheme(scheme)
		corev1.AddToScheme(scheme)

		proxy := &wardenio.WardenProxy{
			ObjectMeta: metav1.ObjectMeta{Name: "warden", Namespace: "default"},
			Spec: wardenio.WardenProxySpec{
				Image: "warden:latest",
				MultiTenant: &wardenio.MultiTenantSpec{
					CertificateIssuerRef: wardenio.IssuerReference{Name: "issuer", Kind: "Issuer"},
				},
			},
		}
		tenant := &wardenio.Tenant{
			ObjectMeta: metav1.ObjectMeta{Name: tenantName, Namespace: "default"},
			Status: wardenio.TenantStatus{
				CertificateSecretName: "warden-tenant-" + tenantName + "-cert",
			},
		}

		cl := fake.NewClientBuilder().WithScheme(scheme).WithRuntimeObjects(proxy, tenant).Build()
		m := &PodMutator{Client: cl, Decoder: admission.NewDecoder(scheme)}

		pod := &corev1.Pod{
			ObjectMeta: metav1.ObjectMeta{
				Name:   "fuzz-pod",
				Labels: map[string]string{"wardenproxy.dev/tenant": tenantName},
			},
			Spec: corev1.PodSpec{
				Containers: []corev1.Container{{Name: containerName, Image: image}},
			},
		}

		raw, err := json.Marshal(pod)
		if err != nil {
			return
		}

		req := admission.Request{
			AdmissionRequest: admissionv1.AdmissionRequest{
				Namespace: "default",
				Object:    runtime.RawExtension{Raw: raw},
			},
		}

		resp := m.Handle(context.Background(), req)
		if !resp.Allowed {
			return
		}

		if len(resp.Patches) == 0 {
			return
		}

		var obj map[string]any
		if err := json.Unmarshal(raw, &obj); err != nil {
			return
		}

		for _, p := range resp.Patches {
			applyJSONPatchOp(t, obj, p.Operation, p.Path, p.Value)
		}

		patched, err := json.Marshal(obj)
		if err != nil {
			t.Fatalf("marshal patched: %v", err)
		}

		var result corev1.Pod
		if err := json.Unmarshal(patched, &result); err != nil {
			t.Fatalf("unmarshal patched pod: %v", err)
		}
	})
}
