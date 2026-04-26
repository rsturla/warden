package webhook

import (
	"context"
	"encoding/json"
	"net/http"
	"strconv"
	"testing"

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
	return &PodMutator{
		Client:  cl,
		Decoder: admission.NewDecoder(scheme),
	}
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

func testTenant(ns, name string) *wardenio.Tenant {
	return &wardenio.Tenant{
		ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: ns},
		Status: wardenio.TenantStatus{
			CertificateSecretName: "warden-tenant-" + name + "-cert",
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

	// Re-encode the original through the webhook's admission response mechanism:
	// marshal the patched JSON (original + patches applied by controller-runtime).
	// controller-runtime already applies patches internally when building the response,
	// so we rebuild the pod from the raw object and apply patches via map manipulation.
	var obj map[string]any
	if err := json.Unmarshal(raw, &obj); err != nil {
		t.Fatal(err)
	}

	for _, p := range resp.Patches {
		applyJSONPatchOp(t, obj, p.Operation, p.Path, p.Value)
	}

	patched, err := json.Marshal(obj)
	if err != nil {
		t.Fatal(err)
	}

	var pod corev1.Pod
	if err := json.Unmarshal(patched, &pod); err != nil {
		t.Fatalf("unmarshaling patched pod: %v", err)
	}
	return &pod
}

func applyJSONPatchOp(t *testing.T, obj map[string]any, op, path string, value any) {
	t.Helper()
	parts := splitJSONPointer(path)
	if len(parts) == 0 {
		t.Fatalf("empty JSON pointer path: %q", path)
	}

	var current any = obj
	for _, key := range parts[:len(parts)-1] {
		current = traverseJSON(t, current, key, path)
	}

	last := parts[len(parts)-1]
	switch parent := current.(type) {
	case map[string]any:
		switch op {
		case "add":
			if existing, ok := parent[last]; ok {
				if arr, ok := existing.([]any); ok {
					parent[last] = append(arr, value)
					return
				}
			}
			parent[last] = value
		case "replace":
			parent[last] = value
		case "remove":
			delete(parent, last)
		}
	case []any:
		idx, err := strconv.Atoi(last)
		if err != nil {
			t.Fatalf("non-numeric array index %q in path %q", last, path)
		}
		switch op {
		case "add":
			if idx == len(parent) {
				setArrayInParent(t, obj, parts[:len(parts)-1], append(parent, value))
			} else {
				expanded := append(parent[:idx+1], parent[idx:]...)
				expanded[idx] = value
				setArrayInParent(t, obj, parts[:len(parts)-1], expanded)
			}
		case "replace":
			parent[idx] = value
		case "remove":
			setArrayInParent(t, obj, parts[:len(parts)-1], append(parent[:idx], parent[idx+1:]...))
		}
	default:
		t.Fatalf("cannot apply op to %T at path %q", current, path)
	}
}

func traverseJSON(t *testing.T, current any, key, fullPath string) any {
	t.Helper()
	switch v := current.(type) {
	case map[string]any:
		return v[key]
	case []any:
		idx, err := strconv.Atoi(key)
		if err != nil {
			t.Fatalf("non-numeric array index %q in path %q", key, fullPath)
		}
		return v[idx]
	default:
		t.Fatalf("cannot traverse path %q at key %q (type %T)", fullPath, key, current)
		return nil
	}
}

func setArrayInParent(t *testing.T, root map[string]any, pathToArray []string, arr []any) {
	t.Helper()
	var current any = root
	for _, key := range pathToArray[:len(pathToArray)-1] {
		current = traverseJSON(t, current, key, "")
	}
	parent := current.(map[string]any)
	parent[pathToArray[len(pathToArray)-1]] = arr
}

func splitJSONPointer(path string) []string {
	if path == "" || path == "/" {
		return nil
	}
	if path[0] == '/' {
		path = path[1:]
	}
	var result []string
	start := 0
	for i := 0; i < len(path); i++ {
		if path[i] == '/' {
			result = append(result, path[start:i])
			start = i + 1
		}
	}
	result = append(result, path[start:])
	return result
}

func TestPodMutator_NoLabel(t *testing.T) {
	m := newTestMutator(t, testProxy("default"), testTenant("default", "alpha"))
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
	m := newTestMutator(t, testProxy("default"), testTenant("default", "alpha"))
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
	m := newTestMutator(t, testProxy("default"), testTenant("default", "alpha"))
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
	for _, c := range patched.Spec.InitContainers {
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
			if c.RestartPolicy == nil || *c.RestartPolicy != corev1.ContainerRestartPolicyAlways {
				t.Error("bridge should have RestartPolicy=Always (native sidecar)")
			}
		}
	}
	if !foundBridge {
		t.Error("bridge container not injected")
	}
}

func TestPodMutator_InjectsEnvVars(t *testing.T) {
	m := newTestMutator(t, testProxy("default"), testTenant("default", "alpha"))
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
	m := newTestMutator(t, testProxy("default"), testTenant("default", "alpha"))
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
	m := newTestMutator(t, testProxy("default"), testTenant("default", "alpha"))
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
	m := newTestMutator(t, testProxy("default"), testTenant("default", "alpha"))
	pod := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Name: "test",
			Labels: map[string]string{
				labelInject: "true",
				labelTenant: "alpha",
			},
		},
		Spec: corev1.PodSpec{
			Containers:     []corev1.Container{{Name: "app", Image: "test:latest"}},
			InitContainers: []corev1.Container{{Name: bridgeName, Image: "warden:latest"}},
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
	m := newTestMutator(t, testProxy("default"), testTenant("default", "alpha"))
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

func TestPodMutator_ExternalCertSecret(t *testing.T) {
	tenant := &wardenio.Tenant{
		ObjectMeta: metav1.ObjectMeta{Name: "ext-cert", Namespace: "default"},
		Spec: wardenio.TenantSpec{
			CertificateSecretName: "my-custom-cert-secret",
		},
		Status: wardenio.TenantStatus{
			CertificateSecretName: "my-custom-cert-secret",
		},
	}
	m := newTestMutator(t, testProxy("default"), tenant)
	pod := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Name: "test",
			Labels: map[string]string{
				labelInject: "true",
				labelTenant: "ext-cert",
			},
		},
		Spec: corev1.PodSpec{Containers: []corev1.Container{{Name: "app", Image: "test:latest"}}},
	}

	resp := m.Handle(context.Background(), admissionRequest(t, pod, "default"))
	patched := applyPatch(t, pod, resp)

	var found bool
	for _, v := range patched.Spec.Volumes {
		if v.Name == certVolName && v.Secret != nil && v.Secret.SecretName == "my-custom-cert-secret" {
			found = true
		}
	}
	if !found {
		t.Error("expected volume with custom secret name 'my-custom-cert-secret'")
	}
}

func TestPodMutator_MultipleContainers(t *testing.T) {
	m := newTestMutator(t, testProxy("default"), testTenant("default", "alpha"), testTenant("default", "beta"))
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

	if len(patched.Spec.Containers) != 2 {
		t.Fatalf("expected 2 containers (app1 + app2), got %d", len(patched.Spec.Containers))
	}
	if len(patched.Spec.InitContainers) != 1 || patched.Spec.InitContainers[0].Name != bridgeName {
		t.Fatalf("expected 1 init container (bridge), got %d", len(patched.Spec.InitContainers))
	}

	for _, c := range patched.Spec.Containers {
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
