package controller

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/kubernetes/scheme"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/envtest"

	wardenio "github.com/rsturla/warden/operator/api/v1alpha1"
	"github.com/rsturla/warden/pkg/api"
)

var (
	testClient client.Client
	testCtx    context.Context
	testCancel context.CancelFunc
	testEnv    *envtest.Environment
)

func TestMain(m *testing.M) {
	if os.Getenv("KUBEBUILDER_ASSETS") == "" {
		// Envtest binaries not available — run non-envtest tests only
		os.Exit(m.Run())
	}

	crdPaths := filepath.Join("..", "..", "config", "crd", "bases")

	testEnv = &envtest.Environment{
		CRDDirectoryPaths: []string{crdPaths},
	}

	cfg, err := testEnv.Start()
	if err != nil {
		panic("starting envtest: " + err.Error())
	}

	if err := wardenio.AddToScheme(scheme.Scheme); err != nil {
		panic(err)
	}

	testClient, err = client.New(cfg, client.Options{Scheme: scheme.Scheme})
	if err != nil {
		panic(err)
	}

	testCtx, testCancel = context.WithCancel(context.Background())

	mgr, err := ctrl.NewManager(cfg, ctrl.Options{
		Scheme: scheme.Scheme,
	})
	if err != nil {
		panic(err)
	}

	if err := (&TenantReconciler{
		Client: mgr.GetClient(),
		Scheme: mgr.GetScheme(),
	}).SetupWithManager(mgr); err != nil {
		panic(err)
	}

	if err := (&WardenProxyReconciler{
		Client: mgr.GetClient(),
		Scheme: mgr.GetScheme(),
	}).SetupWithManager(mgr); err != nil {
		panic(err)
	}

	go func() {
		if err := mgr.Start(testCtx); err != nil {
			panic("manager failed: " + err.Error())
		}
	}()

	code := m.Run()

	testCancel()
	testEnv.Stop()
	os.Exit(code)
}

func requireEnvTest(t *testing.T) {
	t.Helper()
	if os.Getenv("KUBEBUILDER_ASSETS") == "" {
		t.Skip("KUBEBUILDER_ASSETS not set, skipping envtest")
	}
}

func waitFor(t *testing.T, timeout time.Duration, check func() bool) {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if check() {
			return
		}
		time.Sleep(100 * time.Millisecond)
	}
	t.Fatal("timed out waiting for condition")
}

func TestEnvTest_TenantReconcile_CreatesConfigMap(t *testing.T) {
	requireEnvTest(t)
	ns := &corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: "test-tenant-cm"}}
	if err := testClient.Create(testCtx, ns); err != nil {
		t.Fatal(err)
	}

	proxy := &wardenio.WardenProxy{
		ObjectMeta: metav1.ObjectMeta{Name: "warden", Namespace: ns.Name},
		Spec:       wardenio.WardenProxySpec{Image: "warden:latest"},
	}
	if err := testClient.Create(testCtx, proxy); err != nil {
		t.Fatal(err)
	}

	tenant := &wardenio.Tenant{
		ObjectMeta: metav1.ObjectMeta{Name: "alpha", Namespace: ns.Name},
		Spec: wardenio.TenantSpec{
			Policies: []api.PolicyRule{
				{Name: "allow", Host: "example.com", Action: "allow"},
			},
			Secrets: []api.SecretConfig{{Type: "env"}},
		},
	}
	if err := testClient.Create(testCtx, tenant); err != nil {
		t.Fatal(err)
	}

	var cm corev1.ConfigMap
	waitFor(t, 10*time.Second, func() bool {
		err := testClient.Get(testCtx, types.NamespacedName{
			Name: "warden-tenants", Namespace: ns.Name,
		}, &cm)
		return err == nil && cm.Data != nil && cm.Data["alpha.yaml"] != ""
	})

	if cm.Data["alpha.yaml"] == "" {
		t.Fatal("configmap missing alpha.yaml key")
	}
}

func TestEnvTest_TenantReconcile_UpdatesStatus(t *testing.T) {
	requireEnvTest(t)
	ns := &corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: "test-tenant-status"}}
	if err := testClient.Create(testCtx, ns); err != nil {
		t.Fatal(err)
	}

	proxy := &wardenio.WardenProxy{
		ObjectMeta: metav1.ObjectMeta{Name: "warden", Namespace: ns.Name},
		Spec:       wardenio.WardenProxySpec{Image: "warden:latest"},
	}
	if err := testClient.Create(testCtx, proxy); err != nil {
		t.Fatal(err)
	}

	tenant := &wardenio.Tenant{
		ObjectMeta: metav1.ObjectMeta{Name: "beta", Namespace: ns.Name},
		Spec: wardenio.TenantSpec{
			Policies: []api.PolicyRule{
				{Name: "deny", Host: "evil.com", Action: "deny"},
			},
		},
	}
	if err := testClient.Create(testCtx, tenant); err != nil {
		t.Fatal(err)
	}

	var updated wardenio.Tenant
	waitFor(t, 10*time.Second, func() bool {
		if err := testClient.Get(testCtx, types.NamespacedName{Name: "beta", Namespace: ns.Name}, &updated); err != nil {
			return false
		}
		return updated.Status.Ready
	})

	if updated.Status.ConfigMapName != "warden-tenants" {
		t.Errorf("configMapName = %q", updated.Status.ConfigMapName)
	}
}

func TestEnvTest_TenantDelete_RemovesFromConfigMap(t *testing.T) {
	requireEnvTest(t)
	ns := &corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: "test-tenant-delete"}}
	if err := testClient.Create(testCtx, ns); err != nil {
		t.Fatal(err)
	}

	proxy := &wardenio.WardenProxy{
		ObjectMeta: metav1.ObjectMeta{Name: "warden", Namespace: ns.Name},
		Spec:       wardenio.WardenProxySpec{Image: "warden:latest"},
	}
	if err := testClient.Create(testCtx, proxy); err != nil {
		t.Fatal(err)
	}

	tenant := &wardenio.Tenant{
		ObjectMeta: metav1.ObjectMeta{Name: "gamma", Namespace: ns.Name},
		Spec: wardenio.TenantSpec{
			Policies: []api.PolicyRule{
				{Name: "allow", Host: "example.com", Action: "allow"},
			},
		},
	}
	if err := testClient.Create(testCtx, tenant); err != nil {
		t.Fatal(err)
	}

	var cm corev1.ConfigMap
	waitFor(t, 10*time.Second, func() bool {
		err := testClient.Get(testCtx, types.NamespacedName{Name: "warden-tenants", Namespace: ns.Name}, &cm)
		return err == nil && cm.Data["gamma.yaml"] != ""
	})

	if err := testClient.Delete(testCtx, tenant); err != nil {
		t.Fatal(err)
	}

	waitFor(t, 10*time.Second, func() bool {
		if err := testClient.Get(testCtx, types.NamespacedName{Name: "warden-tenants", Namespace: ns.Name}, &cm); err != nil {
			return false
		}
		_, exists := cm.Data["gamma.yaml"]
		return !exists
	})
}

func TestEnvTest_WardenProxyReconcile_CreatesResources(t *testing.T) {
	requireEnvTest(t)
	ns := &corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: "test-proxy-create"}}
	if err := testClient.Create(testCtx, ns); err != nil {
		t.Fatal(err)
	}

	proxy := &wardenio.WardenProxy{
		ObjectMeta: metav1.ObjectMeta{Name: "warden", Namespace: ns.Name},
		Spec: wardenio.WardenProxySpec{
			Image: "warden:latest",
			DNS: &wardenio.DNSSpec{
				DenyResolvedIPs: []string{"169.254.0.0/16"},
			},
		},
	}
	if err := testClient.Create(testCtx, proxy); err != nil {
		t.Fatal(err)
	}

	var configCM corev1.ConfigMap
	waitFor(t, 10*time.Second, func() bool {
		err := testClient.Get(testCtx, types.NamespacedName{Name: "warden-config", Namespace: ns.Name}, &configCM)
		return err == nil
	})
	if configCM.Data["config.yaml"] == "" {
		t.Error("config.yaml missing from config configmap")
	}

	var svc corev1.Service
	waitFor(t, 10*time.Second, func() bool {
		err := testClient.Get(testCtx, types.NamespacedName{Name: "warden", Namespace: ns.Name}, &svc)
		return err == nil
	})
	if len(svc.Spec.Ports) == 0 {
		t.Error("service has no ports")
	}

	var updated wardenio.WardenProxy
	waitFor(t, 10*time.Second, func() bool {
		if err := testClient.Get(testCtx, types.NamespacedName{Name: "warden", Namespace: ns.Name}, &updated); err != nil {
			return false
		}
		return updated.Status.Ready
	})
	if updated.Status.Endpoint == "" {
		t.Error("endpoint not set in status")
	}
}

func TestEnvTest_MultipleTenants_SharedConfigMap(t *testing.T) {
	requireEnvTest(t)
	ns := &corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: "test-multi-tenant"}}
	if err := testClient.Create(testCtx, ns); err != nil {
		t.Fatal(err)
	}

	proxy := &wardenio.WardenProxy{
		ObjectMeta: metav1.ObjectMeta{Name: "warden", Namespace: ns.Name},
		Spec:       wardenio.WardenProxySpec{Image: "warden:latest"},
	}
	if err := testClient.Create(testCtx, proxy); err != nil {
		t.Fatal(err)
	}

	for _, name := range []string{"tenant-a", "tenant-b", "tenant-c"} {
		tenant := &wardenio.Tenant{
			ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: ns.Name},
			Spec: wardenio.TenantSpec{
				Policies: []api.PolicyRule{
					{Name: "allow-" + name, Host: name + ".example.com", Action: "allow"},
				},
			},
		}
		if err := testClient.Create(testCtx, tenant); err != nil {
			t.Fatal(err)
		}
	}

	var cm corev1.ConfigMap
	waitFor(t, 15*time.Second, func() bool {
		err := testClient.Get(testCtx, types.NamespacedName{Name: "warden-tenants", Namespace: ns.Name}, &cm)
		if err != nil {
			return false
		}
		return cm.Data["tenant-a.yaml"] != "" && cm.Data["tenant-b.yaml"] != "" && cm.Data["tenant-c.yaml"] != ""
	})

	if len(cm.Data) != 3 {
		t.Errorf("expected 3 keys in configmap, got %d", len(cm.Data))
	}
}
