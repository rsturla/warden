package controller

import (
	"context"
	"fmt"
	"strings"

	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/types"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller/controllerutil"
	"sigs.k8s.io/controller-runtime/pkg/log"

	wardenio "github.com/rsturla/warden/operator/api/v1alpha1"
	"github.com/rsturla/warden/pkg/api"
	"go.yaml.in/yaml/v3"
)

const (
	tenantFinalizer   = "wardenproxy.dev/tenant-cleanup"
	condTypeSynced    = "Synced"
	condTypeCertReady = "CertificateReady"
)

type TenantReconciler struct {
	client.Client
	Scheme *runtime.Scheme
}

// +kubebuilder:rbac:groups=wardenproxy.dev,resources=tenants,verbs=get;list;watch;update;patch
// +kubebuilder:rbac:groups=wardenproxy.dev,resources=tenants/status,verbs=get;update;patch
// +kubebuilder:rbac:groups=wardenproxy.dev,resources=tenants/finalizers,verbs=update
// +kubebuilder:rbac:groups=wardenproxy.dev,resources=wardenproxies,verbs=get;list;watch
// +kubebuilder:rbac:groups="",resources=configmaps,verbs=get;list;watch;create;update;patch
// +kubebuilder:rbac:groups=cert-manager.io,resources=certificates,verbs=get;list;watch;create;update;patch;delete

func (r *TenantReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	logger := log.FromContext(ctx)

	var tenant wardenio.Tenant
	if err := r.Get(ctx, req.NamespacedName, &tenant); err != nil {
		return ctrl.Result{}, client.IgnoreNotFound(err)
	}

	if !tenant.DeletionTimestamp.IsZero() {
		return r.reconcileDelete(ctx, &tenant)
	}

	if !controllerutil.ContainsFinalizer(&tenant, tenantFinalizer) {
		controllerutil.AddFinalizer(&tenant, tenantFinalizer)
		if err := r.Update(ctx, &tenant); err != nil {
			return ctrl.Result{}, err
		}
	}

	proxy, err := r.findWardenProxy(ctx, tenant.Namespace)
	if err != nil {
		logger.Error(err, "no WardenProxy found")
		r.setCondition(&tenant, condTypeSynced, metav1.ConditionFalse, "NoWardenProxy", err.Error())
		return ctrl.Result{}, r.Status().Update(ctx, &tenant)
	}

	if err := r.reconcileConfigMap(ctx, &tenant, proxy); err != nil {
		logger.Error(err, "configmap sync failed")
		r.setCondition(&tenant, condTypeSynced, metav1.ConditionFalse, "ConfigMapFailed", err.Error())
		return ctrl.Result{}, r.Status().Update(ctx, &tenant)
	}

	if proxy.Spec.MultiTenant != nil {
		if tenant.Spec.CertificateSecretName != "" {
			tenant.Status.CertificateSecretName = tenant.Spec.CertificateSecretName
			r.setCondition(&tenant, condTypeCertReady, metav1.ConditionTrue, "ExternalCertificate", "using pre-existing certificate secret")
		} else {
			if err := r.reconcileCertificate(ctx, &tenant, proxy); err != nil {
				logger.Error(err, "certificate sync failed")
				r.setCondition(&tenant, condTypeCertReady, metav1.ConditionFalse, "CertificateFailed", err.Error())
				_ = r.Status().Update(ctx, &tenant)
				return ctrl.Result{}, err
			}
			r.setCondition(&tenant, condTypeCertReady, metav1.ConditionTrue, "CertificateCreated", "cert-manager Certificate created")
			tenant.Status.CertificateSecretName = certSecretName(tenant.Name)
		}
	}

	r.setCondition(&tenant, condTypeSynced, metav1.ConditionTrue, "Synced", "tenant config synced")
	tenant.Status.Ready = true
	tenant.Status.ObservedGeneration = tenant.Generation
	tenant.Status.ConfigMapName = configMapName(proxy)

	return ctrl.Result{}, r.Status().Update(ctx, &tenant)
}

func (r *TenantReconciler) reconcileDelete(ctx context.Context, tenant *wardenio.Tenant) (ctrl.Result, error) {
	if controllerutil.ContainsFinalizer(tenant, tenantFinalizer) {
		proxy, err := r.findWardenProxy(ctx, tenant.Namespace)
		if err == nil {
			_ = r.removeTenantFromConfigMap(ctx, tenant.Name, proxy)
		}

		controllerutil.RemoveFinalizer(tenant, tenantFinalizer)
		if err := r.Update(ctx, tenant); err != nil {
			return ctrl.Result{}, err
		}
	}
	return ctrl.Result{}, nil
}

func (r *TenantReconciler) reconcileConfigMap(ctx context.Context, tenant *wardenio.Tenant, proxy *wardenio.WardenProxy) error {
	tenantYAML, err := serializeTenantConfig(tenant)
	if err != nil {
		return fmt.Errorf("serializing tenant config: %w", err)
	}

	cmName := configMapName(proxy)
	key := tenant.Name + ".yaml"

	var cm corev1.ConfigMap
	err = r.Get(ctx, types.NamespacedName{Name: cmName, Namespace: tenant.Namespace}, &cm)
	if apierrors.IsNotFound(err) {
		cm = corev1.ConfigMap{
			ObjectMeta: metav1.ObjectMeta{
				Name:      cmName,
				Namespace: tenant.Namespace,
			},
			Data: map[string]string{key: tenantYAML},
		}
		if err := controllerutil.SetOwnerReference(proxy, &cm, r.Scheme); err != nil {
			return fmt.Errorf("setting owner: %w", err)
		}
		return r.Create(ctx, &cm)
	}
	if err != nil {
		return fmt.Errorf("getting configmap: %w", err)
	}

	if cm.Data == nil {
		cm.Data = make(map[string]string)
	}
	if cm.Data[key] == tenantYAML {
		return nil
	}
	cm.Data[key] = tenantYAML
	return r.Update(ctx, &cm)
}

func (r *TenantReconciler) removeTenantFromConfigMap(ctx context.Context, tenantName string, proxy *wardenio.WardenProxy) error {
	cmName := configMapName(proxy)

	var cm corev1.ConfigMap
	if err := r.Get(ctx, types.NamespacedName{Name: cmName, Namespace: proxy.Namespace}, &cm); err != nil {
		return client.IgnoreNotFound(err)
	}

	key := tenantName + ".yaml"
	if _, ok := cm.Data[key]; !ok {
		return nil
	}
	delete(cm.Data, key)
	return r.Update(ctx, &cm)
}

func (r *TenantReconciler) reconcileCertificate(ctx context.Context, tenant *wardenio.Tenant, proxy *wardenio.WardenProxy) error {
	certName := "warden-tenant-" + tenant.Name
	issuer := proxy.Spec.MultiTenant.CertificateIssuerRef

	cert := &unstructured.Unstructured{}
	cert.SetGroupVersionKind(schema.GroupVersionKind{
		Group:   "cert-manager.io",
		Version: "v1",
		Kind:    "Certificate",
	})

	err := r.Get(ctx, types.NamespacedName{Name: certName, Namespace: tenant.Namespace}, cert)
	if apierrors.IsNotFound(err) {
		cert.Object = map[string]any{
			"apiVersion": "cert-manager.io/v1",
			"kind":       "Certificate",
			"metadata": map[string]any{
				"name":      certName,
				"namespace": tenant.Namespace,
			},
			"spec": map[string]any{
				"secretName": certSecretName(tenant.Name),
				"commonName": tenant.Name,
				"usages":     []any{"client auth", "digital signature"},
				"privateKey": map[string]any{
					"algorithm": "ECDSA",
					"size":      int64(256),
				},
				"issuerRef": map[string]any{
					"name": issuer.Name,
					"kind": issuer.Kind,
				},
			},
		}
		if err := controllerutil.SetOwnerReference(tenant, cert, r.Scheme); err != nil {
			return fmt.Errorf("setting owner: %w", err)
		}
		return r.Create(ctx, cert)
	}
	return err
}

func (r *TenantReconciler) findWardenProxy(ctx context.Context, namespace string) (*wardenio.WardenProxy, error) {
	var list wardenio.WardenProxyList
	if err := r.List(ctx, &list, client.InNamespace(namespace)); err != nil {
		return nil, fmt.Errorf("listing WardenProxy: %w", err)
	}
	if len(list.Items) == 0 {
		return nil, fmt.Errorf("no WardenProxy in namespace %s", namespace)
	}
	return &list.Items[0], nil
}

func (r *TenantReconciler) setCondition(tenant *wardenio.Tenant, condType string, status metav1.ConditionStatus, reason, message string) {
	meta.SetStatusCondition(&tenant.Status.Conditions, metav1.Condition{
		Type:               condType,
		Status:             status,
		ObservedGeneration: tenant.Generation,
		Reason:             reason,
		Message:            message,
	})
}

func (r *TenantReconciler) SetupWithManager(mgr ctrl.Manager) error {
	return ctrl.NewControllerManagedBy(mgr).
		For(&wardenio.Tenant{}).
		Owns(&corev1.ConfigMap{}).
		Complete(r)
}

func serializeTenantConfig(tenant *wardenio.Tenant) (string, error) {
	policies := make([]api.PolicyRule, len(tenant.Spec.Policies))
	copy(policies, tenant.Spec.Policies)
	for i := range policies {
		policies[i].Name = sanitizeField(policies[i].Name)
		policies[i].Host = sanitizeField(policies[i].Host)
		policies[i].Path = sanitizeField(policies[i].Path)
		policies[i].Action = sanitizeField(policies[i].Action)
		for j := range policies[i].Methods {
			policies[i].Methods[j] = sanitizeField(policies[i].Methods[j])
		}
		if policies[i].Name == "" {
			return "", fmt.Errorf("policy %d: name is empty after sanitization", i)
		}
		if policies[i].Host == "" {
			return "", fmt.Errorf("policy %q: host is empty after sanitization", policies[i].Name)
		}
	}

	tc := api.TenantConfig{
		Policies: policies,
		Secrets:  tenant.Spec.Secrets,
	}
	data, err := yaml.Marshal(tc)
	if err != nil {
		return "", err
	}
	return string(data), nil
}

func sanitizeField(s string) string {
	return strings.Map(func(r rune) rune {
		if r == '\n' || r == '\r' {
			return -1
		}
		return r
	}, s)
}

func configMapName(proxy *wardenio.WardenProxy) string {
	return proxy.Name + "-tenants"
}

func certSecretName(tenantName string) string {
	return "warden-tenant-" + tenantName + "-cert"
}
