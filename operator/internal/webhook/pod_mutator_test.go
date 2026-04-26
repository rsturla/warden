package webhook

import (
	"context"
	"encoding/json"
	"net/http"
	"testing"

	jsonpatch "github.com/evanphx/json-patch/v5"
	admissionv1 "k8s.io/api/admission/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
	"sigs.k8s.io/controller-runtime/pkg/webhook/admission"

	wardenio "github.com/rsturla/warden/operator/api/v1alpha1"
)

func newTestMutator(t *testing.T, objs ...runtime.Object) *PodMutator {
	t.Helper()
	scheme := runtime.NewScheme()
	if err := wardenio.AddToScheme(scheme); err != nil {
		t.Fatal(err)
	}
	if err := corev1.AddToScheme(scheme); err != nil {
		t.Fatal(err)
	}
	cl := fake.NewClientBuilder().WithScheme(scheme).WithRuntimeObjects(objs...).Build()
	decoder := admission.NewDecoder(scheme)
	m := &PodMutator{Client: cl}
	m.InjectDecoder(decoder)
	return m
}

func testProxy(ns string) *wardenio.WardenProxy {
	return &wardenio.WardenProxy{
		ObjectMeta: metav1.ObjectMeta{Name: "warden", Namespace: ns},
		Spec: wardenio.WardenProxySpec{
			Image: "warden:latest",
			MultiTenant: &wardenio.MultiTenantSpec{
				CertificateIssuerRef: wardenio.IssuerReference{Name: "test-issuer", Kind: "Issuer"},
			},
		},
	}
}

func admissionRequest(t *testing.T, pod *corev1.Pod, ns string) admission.Request {
	t.Helper()
	raw, err := json.Marshal(pod)
	if err != nil {
		t.Fatal(err)
	}
	return admission.Request{
		AdmissionRequest: admissionv1.AdmissionRequest{
			Namespace: ns,
			Object:    runtime.RawExtension{Raw: raw},
		},
	}
}

func applyPatch(t *testing.T, original *corev1.Pod, resp admission.Response) *corev1.Pod {
	t.Helper()
	if !resp.Allowed {
		t.Fatalf("response not allowed: %s", resp.Result.Message)
	}

	raw, err := json.Marshal(original)
	if err != nil {
		t.Fatal(err)
	}

	if len(resp.Patches) == 0 {
		var p corev1.Pod
		if err := json.Unmarshal(raw, &p); err != nil {
			t.Fatal(err)
		}
		return &p
	}

	patchBytes, err := json.Marshal(resp.Patches)
	if err != nil {
		t.Fatalf("marshaling patches: %v", err)
	}

	patch, err := jsonpatch.DecodePatch(patchBytes)
	if err != nil {
		t.Fatalf("decoding patch: %v", err)
	}

	patched, err := patch.Apply(raw)
	if err != nil {
		t.Fatalf("applying patch: %v", err)
	}

	var pod corev1.Pod
	if err := json.Unmarshal(patched, &pod); err != nil {
		t.Fatalf("unmarshaling patched pod: %v", err)
	}
	return &pod
}

func TestPodMutator_NoLabel(t *testing.T) {
	m := newTestMutator(t, testProxy("default"))
	pod := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{Name: "test", Labels: map[string]string{}},
		Spec:       corev1.PodSpec{Containers: []corev1.Container{{Name: "app", Image: "test:latest"}}},
	}

	resp := m.Handle(context.Background(), admissionRequest(t, pod, "default"))
	if !resp.Allowed {
		t.Fatalf("expected allowed, got denied: %s", resp.Result.Message)
	}
}

func TestPodMutator_InjectLabel_NoTenant(t *testing.T) {
	m := newTestMutator(t, testProxy("default"))
	pod := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Name:   "test",
			Labels: map[string]string{labelInject: "true"},
		},
		Spec: corev1.PodSpec{Containers: []corev1.Container{{Name: "app", Image: "test:latest"}}},
	}

	resp := m.Handle(context.Background(), admissionRequest(t, pod, "default"))
	if resp.Allowed {
		t.Fatal("expected denied when tenant label missing")
	}
}

func TestPodMutator_InjectsBridge(t *testing.T) {
	m := newTestMutator(t, testProxy("default"))
	pod := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Name: "test",
			Labels: map[string]string{
				labelInject: "true",
				labelTenant: "alpha",
			},
		},
		Spec: corev1.PodSpec{Containers: []corev1.Container{{Name: "app", Image: "test:latest"}}},
	}

	resp := m.Handle(context.Background(), admissionRequest(t, pod, "default"))
	if !resp.Allowed {
		t.Fatalf("expected allowed, got: %s (code: %d)", resp.Result.Message, resp.Result.Code)
	}

	patched := applyPatch(t, pod, resp)

	var foundBridge bool
	for _, c := range patched.Spec.Containers {
		if c.Name == bridgeName {
			foundBridge = true
			if c.Image != "warden:latest" {
				t.Errorf("bridge image = %q, want warden:latest", c.Image)
			}
			if len(c.Args) == 0 {
				t.Error("bridge has no args")
			}
			if len(c.VolumeMounts) == 0 {
				t.Error("bridge has no volume mounts")
			}
		}
	}
	if !foundBridge {
		t.Error("bridge container not injected")
	}
}

func TestPodMutator_InjectsEnvVars(t *testing.T) {
	m := newTestMutator(t, testProxy("default"))
	pod := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Name: "test",
			Labels: map[string]string{
				labelInject: "true",
				labelTenant: "alpha",
			},
		},
		Spec: corev1.PodSpec{Containers: []corev1.Container{{Name: "app", Image: "test:latest"}}},
	}

	resp := m.Handle(context.Background(), admissionRequest(t, pod, "default"))
	patched := applyPatch(t, pod, resp)

	for _, c := range patched.Spec.Containers {
		if c.Name == bridgeName {
			continue
		}
		var hasHTTP, hasHTTPS bool
		for _, e := range c.Env {
			if e.Name == "HTTP_PROXY" && e.Value == "http://127.0.0.1:8080" {
				hasHTTP = true
			}
			if e.Name == "HTTPS_PROXY" && e.Value == "http://127.0.0.1:8080" {
				hasHTTPS = true
			}
		}
		if !hasHTTP {
			t.Errorf("container %q missing HTTP_PROXY", c.Name)
		}
		if !hasHTTPS {
			t.Errorf("container %q missing HTTPS_PROXY", c.Name)
		}
	}
}

func TestPodMutator_InjectsCertVolume(t *testing.T) {
	m := newTestMutator(t, testProxy("default"))
	pod := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Name: "test",
			Labels: map[string]string{
				labelInject: "true",
				labelTenant: "alpha",
			},
		},
		Spec: corev1.PodSpec{Containers: []corev1.Container{{Name: "app", Image: "test:latest"}}},
	}

	resp := m.Handle(context.Background(), admissionRequest(t, pod, "default"))
	patched := applyPatch(t, pod, resp)

	var found bool
	for _, v := range patched.Spec.Volumes {
		if v.Name == certVolName && v.Secret != nil && v.Secret.SecretName == "warden-tenant-alpha-cert" {
			found = true
		}
	}
	if !found {
		t.Error("cert volume not injected or wrong secret name")
	}
}

func TestPodMutator_PreservesExistingEnv(t *testing.T) {
	m := newTestMutator(t, testProxy("default"))
	pod := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Name: "test",
			Labels: map[string]string{
				labelInject: "true",
				labelTenant: "alpha",
			},
		},
		Spec: corev1.PodSpec{Containers: []corev1.Container{{
			Name:  "app",
			Image: "test:latest",
			Env:   []corev1.EnvVar{{Name: "HTTP_PROXY", Value: "http://custom:1234"}},
		}}},
	}

	resp := m.Handle(context.Background(), admissionRequest(t, pod, "default"))
	patched := applyPatch(t, pod, resp)

	for _, c := range patched.Spec.Containers {
		if c.Name == bridgeName {
			continue
		}
		for _, e := range c.Env {
			if e.Name == "HTTP_PROXY" && e.Value != "http://custom:1234" {
				t.Errorf("existing HTTP_PROXY overwritten: %q", e.Value)
			}
		}
	}
}

func TestPodMutator_Idempotent(t *testing.T) {
	m := newTestMutator(t, testProxy("default"))
	pod := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Name: "test",
			Labels: map[string]string{
				labelInject: "true",
				labelTenant: "alpha",
			},
		},
		Spec: corev1.PodSpec{
			Containers: []corev1.Container{
				{Name: "app", Image: "test:latest"},
				{Name: bridgeName, Image: "warden:latest"},
			},
		},
	}

	resp := m.Handle(context.Background(), admissionRequest(t, pod, "default"))
	if !resp.Allowed {
		t.Fatalf("expected allowed, got: %s", resp.Result.Message)
	}
	if len(resp.Patches) > 0 {
		t.Errorf("expected no patches for idempotent case, got %d patches", len(resp.Patches))
	}
}

func TestPodMutator_SetsAgentLabel(t *testing.T) {
	m := newTestMutator(t, testProxy("default"))
	pod := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Name: "test",
			Labels: map[string]string{
				labelInject: "true",
				labelTenant: "alpha",
			},
		},
		Spec: corev1.PodSpec{Containers: []corev1.Container{{Name: "app", Image: "test:latest"}}},
	}

	resp := m.Handle(context.Background(), admissionRequest(t, pod, "default"))
	patched := applyPatch(t, pod, resp)

	if patched.Labels["role"] != "agent" {
		t.Errorf("role label = %q, want agent", patched.Labels["role"])
	}
}

func TestPodMutator_NoProxyInNamespace(t *testing.T) {
	m := newTestMutator(t)
	pod := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Name: "test",
			Labels: map[string]string{
				labelInject: "true",
				labelTenant: "alpha",
			},
		},
		Spec: corev1.PodSpec{Containers: []corev1.Container{{Name: "app", Image: "test:latest"}}},
	}

	resp := m.Handle(context.Background(), admissionRequest(t, pod, "default"))
	if resp.Result.Code != http.StatusInternalServerError {
		t.Errorf("expected 500 when no proxy, got: %d", resp.Result.Code)
	}
}

func TestPodMutator_MultipleContainers(t *testing.T) {
	m := newTestMutator(t, testProxy("default"))
	pod := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Name: "test",
			Labels: map[string]string{
				labelInject: "true",
				labelTenant: "beta",
			},
		},
		Spec: corev1.PodSpec{Containers: []corev1.Container{
			{Name: "app1", Image: "app1:latest"},
			{Name: "app2", Image: "app2:latest"},
		}},
	}

	resp := m.Handle(context.Background(), admissionRequest(t, pod, "default"))
	patched := applyPatch(t, pod, resp)

	if len(patched.Spec.Containers) != 3 {
		t.Fatalf("expected 3 containers (app1 + app2 + bridge), got %d", len(patched.Spec.Containers))
	}

	for _, c := range patched.Spec.Containers {
		if c.Name == bridgeName {
			continue
		}
		var found bool
		for _, e := range c.Env {
			if e.Name == "HTTP_PROXY" {
				found = true
			}
		}
		if !found {
			t.Errorf("container %q missing HTTP_PROXY", c.Name)
		}
	}
}
