package controller

import (
	"context"
	"fmt"

	certmanagerv1 "github.com/cert-manager/cert-manager/pkg/apis/certmanager/v1"
	cmmeta "github.com/cert-manager/cert-manager/pkg/apis/meta/v1"
	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	networkingv1 "k8s.io/api/networking/v1"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/util/intstr"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller/controllerutil"
	"sigs.k8s.io/controller-runtime/pkg/log"

	wardenio "github.com/rsturla/warden/operator/api/v1alpha1"
	"go.yaml.in/yaml/v3"
)

type WardenProxyReconciler struct {
	client.Client
	Scheme *runtime.Scheme
}

// +kubebuilder:rbac:groups=wardenproxy.dev,resources=wardenproxies,verbs=get;list;watch;update;patch
// +kubebuilder:rbac:groups=wardenproxy.dev,resources=wardenproxies/status,verbs=get;update;patch
// +kubebuilder:rbac:groups=apps,resources=deployments,verbs=get;list;watch;create;update;patch;delete
// +kubebuilder:rbac:groups="",resources=services,verbs=get;list;watch;create;update;patch;delete
// +kubebuilder:rbac:groups="",resources=configmaps,verbs=get;list;watch;create;update;patch;delete
// +kubebuilder:rbac:groups=networking.k8s.io,resources=networkpolicies,verbs=get;list;watch;create;update;patch;delete
// +kubebuilder:rbac:groups=cert-manager.io,resources=certificates,verbs=get;list;watch;create;update;patch;delete
// +kubebuilder:rbac:groups=cert-manager.io,resources=issuers,verbs=get;list;watch;create;update;patch;delete

func (r *WardenProxyReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	logger := log.FromContext(ctx)

	var proxy wardenio.WardenProxy
	if err := r.Get(ctx, req.NamespacedName, &proxy); err != nil {
		return ctrl.Result{}, client.IgnoreNotFound(err)
	}

	if err := r.reconcileConfig(ctx, &proxy); err != nil {
		logger.Error(err, "config reconcile failed")
		return ctrl.Result{}, err
	}

	if err := r.reconcileCertificates(ctx, &proxy); err != nil {
		logger.Error(err, "certificate reconcile failed")
		return ctrl.Result{}, err
	}

	if err := r.reconcileDeployment(ctx, &proxy); err != nil {
		logger.Error(err, "deployment reconcile failed")
		return ctrl.Result{}, err
	}

	if err := r.reconcileService(ctx, &proxy); err != nil {
		logger.Error(err, "service reconcile failed")
		return ctrl.Result{}, err
	}

	if err := r.reconcileNetworkPolicies(ctx, &proxy); err != nil {
		logger.Error(err, "network policy reconcile failed")
		return ctrl.Result{}, err
	}

	proxy.Status.Ready = true
	proxy.Status.Endpoint = fmt.Sprintf("%s.%s.svc:%d", proxy.Name, proxy.Namespace, proxyPort(&proxy))
	proxy.Status.ObservedGeneration = proxy.Generation

	tenantCount, _ := r.countTenants(ctx, proxy.Namespace)
	proxy.Status.TenantCount = tenantCount

	meta.SetStatusCondition(&proxy.Status.Conditions, metav1.Condition{
		Type:               "Ready",
		Status:             metav1.ConditionTrue,
		ObservedGeneration: proxy.Generation,
		Reason:             "Reconciled",
		Message:            "all resources created",
	})

	return ctrl.Result{}, r.Status().Update(ctx, &proxy)
}

func (r *WardenProxyReconciler) reconcileConfig(ctx context.Context, proxy *wardenio.WardenProxy) error {
	cfg := buildWardenConfig(proxy)
	data, err := yaml.Marshal(cfg)
	if err != nil {
		return fmt.Errorf("marshaling config: %w", err)
	}

	cmName := proxy.Name + "-config"
	return r.createOrUpdateConfigMap(ctx, proxy, cmName, map[string]string{
		"config.yaml": string(data),
	})
}

func (r *WardenProxyReconciler) reconcileCertificates(ctx context.Context, proxy *wardenio.WardenProxy) error {
	if proxy.Spec.MultiTenant == nil {
		return nil
	}

	issuerRef := cmmeta.ObjectReference{
		Name: proxy.Spec.MultiTenant.CertificateIssuerRef.Name,
		Kind: proxy.Spec.MultiTenant.CertificateIssuerRef.Kind,
	}
	if issuerRef.Kind == "" {
		issuerRef.Kind = "Issuer"
	}
	name := proxy.Name
	ns := proxy.Namespace

	// tenant-ca and server-tls must be signed by the same CA so the bridge
	// can verify the proxy with the ca.crt from its tenant cert Secret.
	// We create the tenant-ca first, then an Issuer from it, and sign
	// both server-tls and tenant certs with that Issuer.
	tenantCA := &certmanagerv1.Certificate{
		ObjectMeta: metav1.ObjectMeta{Name: name + "-tenant-ca", Namespace: ns},
	}
	if _, err := controllerutil.CreateOrUpdate(ctx, r.Client, tenantCA, func() error {
		if err := controllerutil.SetControllerReference(proxy, tenantCA, r.Scheme); err != nil {
			return err
		}
		tenantCA.Spec = certmanagerv1.CertificateSpec{
			SecretName: name + "-tenant-ca",
			IssuerRef:  issuerRef,
			CommonName: name + "-tenant-ca",
			IsCA:       true,
			Usages:     []certmanagerv1.KeyUsage{certmanagerv1.UsageCertSign},
			PrivateKey: &certmanagerv1.CertificatePrivateKey{
				Algorithm: certmanagerv1.ECDSAKeyAlgorithm,
				Size:      256,
			},
		}
		return nil
	}); err != nil {
		return fmt.Errorf("tenant-ca certificate: %w", err)
	}

	tenantIssuer := &certmanagerv1.Issuer{
		ObjectMeta: metav1.ObjectMeta{Name: name + "-tenant-issuer", Namespace: ns},
	}
	if _, err := controllerutil.CreateOrUpdate(ctx, r.Client, tenantIssuer, func() error {
		if err := controllerutil.SetControllerReference(proxy, tenantIssuer, r.Scheme); err != nil {
			return err
		}
		tenantIssuer.Spec = certmanagerv1.IssuerSpec{
			IssuerConfig: certmanagerv1.IssuerConfig{
				CA: &certmanagerv1.CAIssuer{
					SecretName: name + "-tenant-ca",
				},
			},
		}
		return nil
	}); err != nil {
		return fmt.Errorf("tenant-issuer: %w", err)
	}

	tenantIssuerRef := cmmeta.ObjectReference{
		Name: name + "-tenant-issuer",
		Kind: "Issuer",
	}

	serverTLS := &certmanagerv1.Certificate{
		ObjectMeta: metav1.ObjectMeta{Name: name + "-server-tls", Namespace: ns},
	}
	if _, err := controllerutil.CreateOrUpdate(ctx, r.Client, serverTLS, func() error {
		if err := controllerutil.SetControllerReference(proxy, serverTLS, r.Scheme); err != nil {
			return err
		}
		serverTLS.Spec = certmanagerv1.CertificateSpec{
			SecretName: name + "-server-tls",
			IssuerRef:  tenantIssuerRef,
			DNSNames: []string{
				name,
				name + "." + ns,
				name + "." + ns + ".svc",
				name + "." + ns + ".svc.cluster.local",
			},
			Usages: []certmanagerv1.KeyUsage{certmanagerv1.UsageServerAuth},
			PrivateKey: &certmanagerv1.CertificatePrivateKey{
				Algorithm: certmanagerv1.ECDSAKeyAlgorithm,
				Size:      256,
			},
		}
		return nil
	}); err != nil {
		return fmt.Errorf("server-tls certificate: %w", err)
	}

	mitmCA := &certmanagerv1.Certificate{
		ObjectMeta: metav1.ObjectMeta{Name: name + "-mitm-ca", Namespace: ns},
	}
	if _, err := controllerutil.CreateOrUpdate(ctx, r.Client, mitmCA, func() error {
		if err := controllerutil.SetControllerReference(proxy, mitmCA, r.Scheme); err != nil {
			return err
		}
		mitmCA.Spec = certmanagerv1.CertificateSpec{
			SecretName: name + "-mitm-ca",
			IssuerRef:  issuerRef,
			CommonName: name + "-mitm-ca",
			IsCA:       true,
			Usages:     []certmanagerv1.KeyUsage{certmanagerv1.UsageCertSign},
			PrivateKey: &certmanagerv1.CertificatePrivateKey{
				Algorithm: certmanagerv1.ECDSAKeyAlgorithm,
				Size:      256,
			},
		}
		return nil
	}); err != nil {
		return fmt.Errorf("mitm-ca certificate: %w", err)
	}

	return nil
}

func (r *WardenProxyReconciler) reconcileDeployment(ctx context.Context, proxy *wardenio.WardenProxy) error {
	name := proxy.Name
	replicas := int32(1)
	if proxy.Spec.Replicas != nil {
		replicas = *proxy.Spec.Replicas
	}

	labels := map[string]string{"app": name, "wardenproxy.dev/proxy": proxy.Name}

	volumes := []corev1.Volume{
		{Name: "config", VolumeSource: corev1.VolumeSource{ConfigMap: &corev1.ConfigMapVolumeSource{
			LocalObjectReference: corev1.LocalObjectReference{Name: name + "-config"},
			Items:                []corev1.KeyToPath{{Key: "config.yaml", Path: "config.yaml"}},
		}}},
		{Name: "shared-ca", VolumeSource: corev1.VolumeSource{EmptyDir: &corev1.EmptyDirVolumeSource{}}},
	}

	mounts := []corev1.VolumeMount{
		{Name: "config", MountPath: "/etc/warden"},
		{Name: "shared-ca", MountPath: "/shared"},
	}

	if proxy.Spec.MultiTenant != nil {
		volumes = append(volumes,
			corev1.Volume{Name: "tenants", VolumeSource: corev1.VolumeSource{ConfigMap: &corev1.ConfigMapVolumeSource{
				LocalObjectReference: corev1.LocalObjectReference{Name: name + "-tenants"},
			}}},
			corev1.Volume{Name: "server-tls", VolumeSource: corev1.VolumeSource{Secret: &corev1.SecretVolumeSource{
				SecretName: name + "-server-tls",
			}}},
			corev1.Volume{Name: "tenant-ca", VolumeSource: corev1.VolumeSource{Secret: &corev1.SecretVolumeSource{
				SecretName: name + "-tenant-ca",
				Items:      []corev1.KeyToPath{{Key: "tls.crt", Path: "ca.crt"}},
			}}},
			corev1.Volume{Name: "mitm-ca", VolumeSource: corev1.VolumeSource{Secret: &corev1.SecretVolumeSource{
				SecretName: name + "-mitm-ca",
				Items: []corev1.KeyToPath{
					{Key: "tls.crt", Path: "ca.crt"},
					{Key: "tls.key", Path: "ca.key"},
				},
			}}},
		)
		mounts = append(mounts,
			corev1.VolumeMount{Name: "tenants", MountPath: "/etc/warden/tenants.d"},
			corev1.VolumeMount{Name: "server-tls", MountPath: "/etc/warden/tls"},
			corev1.VolumeMount{Name: "tenant-ca", MountPath: "/etc/warden/tenant-ca"},
			corev1.VolumeMount{Name: "mitm-ca", MountPath: "/etc/warden/mitm"},
		)
	}

	volumes = append(volumes, proxy.Spec.ExtraVolumes...)
	mounts = append(mounts, proxy.Spec.ExtraVolumeMounts...)

	deploy := &appsv1.Deployment{
		ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: proxy.Namespace},
	}

	_, err := controllerutil.CreateOrUpdate(ctx, r.Client, deploy, func() error {
		if err := controllerutil.SetControllerReference(proxy, deploy, r.Scheme); err != nil {
			return err
		}
		deploy.Spec = appsv1.DeploymentSpec{
			Replicas: &replicas,
			Selector: &metav1.LabelSelector{MatchLabels: labels},
			Template: corev1.PodTemplateSpec{
				ObjectMeta: metav1.ObjectMeta{Labels: labels},
				Spec: corev1.PodSpec{
					Volumes: volumes,
					Containers: []corev1.Container{{
						Name:            "warden",
						Image:           proxy.Spec.Image,
						ImagePullPolicy: corev1.PullIfNotPresent,
						Args:            []string{"-config", "/etc/warden/config.yaml"},
						Ports: []corev1.ContainerPort{
							{Name: "proxy", ContainerPort: proxyPort(proxy)},
							{Name: "health", ContainerPort: 9090},
						},
						VolumeMounts: mounts,
						LivenessProbe: &corev1.Probe{ProbeHandler: corev1.ProbeHandler{
							HTTPGet: &corev1.HTTPGetAction{Path: "/healthz", Port: intstr.FromInt32(9090)},
						}},
						ReadinessProbe: &corev1.Probe{ProbeHandler: corev1.ProbeHandler{
							HTTPGet: &corev1.HTTPGetAction{Path: "/readyz", Port: intstr.FromInt32(9090)},
						}},
						Resources: proxy.Spec.Resources,
					}},
				},
			},
		}
		return nil
	})
	return err
}

func (r *WardenProxyReconciler) reconcileService(ctx context.Context, proxy *wardenio.WardenProxy) error {
	svc := &corev1.Service{
		ObjectMeta: metav1.ObjectMeta{Name: proxy.Name, Namespace: proxy.Namespace},
	}

	port := proxyPort(proxy)
	_, err := controllerutil.CreateOrUpdate(ctx, r.Client, svc, func() error {
		if err := controllerutil.SetControllerReference(proxy, svc, r.Scheme); err != nil {
			return err
		}
		svc.Spec = corev1.ServiceSpec{
			Selector: map[string]string{"app": proxy.Name},
			Ports: []corev1.ServicePort{
				{Name: "proxy", Port: port, TargetPort: intstr.FromString("proxy")},
				{Name: "health", Port: 9090, TargetPort: intstr.FromString("health")},
			},
		}
		return nil
	})
	return err
}

func (r *WardenProxyReconciler) reconcileNetworkPolicies(ctx context.Context, proxy *wardenio.WardenProxy) error {
	port := proxyPort(proxy)
	protocol := corev1.ProtocolTCP

	// Warden ingress: only accept from agents
	ingressNP := &networkingv1.NetworkPolicy{
		ObjectMeta: metav1.ObjectMeta{Name: proxy.Name + "-ingress", Namespace: proxy.Namespace},
	}
	if _, err := controllerutil.CreateOrUpdate(ctx, r.Client, ingressNP, func() error {
		if err := controllerutil.SetControllerReference(proxy, ingressNP, r.Scheme); err != nil {
			return err
		}
		ingressNP.Spec = networkingv1.NetworkPolicySpec{
			PodSelector: metav1.LabelSelector{MatchLabels: map[string]string{"app": proxy.Name}},
			PolicyTypes: []networkingv1.PolicyType{networkingv1.PolicyTypeIngress},
			Ingress: []networkingv1.NetworkPolicyIngressRule{{
				From: []networkingv1.NetworkPolicyPeer{{
					PodSelector: &metav1.LabelSelector{MatchLabels: map[string]string{"role": "agent"}},
				}},
				Ports: []networkingv1.NetworkPolicyPort{{Port: &intstr.IntOrString{IntVal: port}, Protocol: &protocol}},
			}},
		}
		return nil
	}); err != nil {
		return err
	}

	// Warden egress: allow all outbound
	egressNP := &networkingv1.NetworkPolicy{
		ObjectMeta: metav1.ObjectMeta{Name: proxy.Name + "-egress", Namespace: proxy.Namespace},
	}
	_, err := controllerutil.CreateOrUpdate(ctx, r.Client, egressNP, func() error {
		if err := controllerutil.SetControllerReference(proxy, egressNP, r.Scheme); err != nil {
			return err
		}
		egressNP.Spec = networkingv1.NetworkPolicySpec{
			PodSelector: metav1.LabelSelector{MatchLabels: map[string]string{"app": proxy.Name}},
			PolicyTypes: []networkingv1.PolicyType{networkingv1.PolicyTypeEgress},
			Egress:      []networkingv1.NetworkPolicyEgressRule{{}},
		}
		return nil
	})
	return err
}

func (r *WardenProxyReconciler) countTenants(ctx context.Context, namespace string) (int, error) {
	var list wardenio.TenantList
	if err := r.List(ctx, &list, client.InNamespace(namespace)); err != nil {
		return 0, err
	}
	return len(list.Items), nil
}

func (r *WardenProxyReconciler) createOrUpdateConfigMap(ctx context.Context, proxy *wardenio.WardenProxy, name string, data map[string]string) error {
	cm := &corev1.ConfigMap{
		ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: proxy.Namespace},
	}
	_, err := controllerutil.CreateOrUpdate(ctx, r.Client, cm, func() error {
		if err := controllerutil.SetControllerReference(proxy, cm, r.Scheme); err != nil {
			return err
		}
		cm.Data = data
		return nil
	})
	return err
}

func (r *WardenProxyReconciler) SetupWithManager(mgr ctrl.Manager) error {
	return ctrl.NewControllerManagedBy(mgr).
		For(&wardenio.WardenProxy{}).
		Owns(&appsv1.Deployment{}).
		Owns(&corev1.Service{}).
		Owns(&corev1.ConfigMap{}).
		Owns(&networkingv1.NetworkPolicy{}).
		Owns(&certmanagerv1.Certificate{}).
		Complete(r)
}

func proxyPort(proxy *wardenio.WardenProxy) int32 {
	if proxy.Spec.MultiTenant != nil {
		return 8443
	}
	return 8080
}

type wardenConfig struct {
	Server    wardenServerConfig     `yaml:"server"`
	CA        wardenCAConfig         `yaml:"ca"`
	DNS       *wardenDNSConfig       `yaml:"dns,omitempty"`
	Tenants   *wardenTenantsConfig   `yaml:"tenants,omitempty"`
	Policies  []interface{}          `yaml:"policies,omitempty"`
	Secrets   []interface{}          `yaml:"secrets,omitempty"`
	Telemetry *wardenTelemetryConfig `yaml:"telemetry,omitempty"`
}

type wardenServerConfig struct {
	Listen       string                 `yaml:"listen"`
	HealthListen string                 `yaml:"health_listen"`
	TLS          *wardenServerTLSConfig `yaml:"tls,omitempty"`
}

type wardenServerTLSConfig struct {
	Cert     string `yaml:"cert"`
	Key      string `yaml:"key"`
	ClientCA string `yaml:"client_ca"`
}

type wardenCAConfig struct {
	Auto       bool   `yaml:"auto,omitempty"`
	CertOutput string `yaml:"cert_output,omitempty"`
	Cert       string `yaml:"cert,omitempty"`
	Key        string `yaml:"key,omitempty"`
}

type wardenDNSConfig struct {
	Cache           *wardenCacheConfig `yaml:"cache,omitempty"`
	DenyResolvedIPs []string           `yaml:"deny_resolved_ips,omitempty"`
}

type wardenCacheConfig struct {
	Enabled bool `yaml:"enabled"`
	MaxTTL  int  `yaml:"max_ttl,omitempty"`
}

type wardenTenantsConfig struct {
	Dir string `yaml:"dir"`
}

type wardenTelemetryConfig struct {
	Logs    *wardenLogsConfig    `yaml:"logs,omitempty"`
	Traces  *wardenTracesConfig  `yaml:"traces,omitempty"`
	Metrics *wardenMetricsConfig `yaml:"metrics,omitempty"`
}

type wardenLogsConfig struct {
	Level  string `yaml:"level"`
	Format string `yaml:"format"`
}

type wardenTracesConfig struct {
	Enabled  bool   `yaml:"enabled"`
	Endpoint string `yaml:"endpoint"`
}

type wardenMetricsConfig struct {
	Enabled  bool   `yaml:"enabled"`
	Endpoint string `yaml:"endpoint"`
}

func buildWardenConfig(proxy *wardenio.WardenProxy) wardenConfig {
	cfg := wardenConfig{
		Server: wardenServerConfig{
			Listen:       fmt.Sprintf("0.0.0.0:%d", proxyPort(proxy)),
			HealthListen: "0.0.0.0:9090",
		},
	}

	if proxy.Spec.MultiTenant != nil {
		cfg.Server.TLS = &wardenServerTLSConfig{
			Cert:     "/etc/warden/tls/tls.crt",
			Key:      "/etc/warden/tls/tls.key",
			ClientCA: "/etc/warden/tenant-ca/ca.crt",
		}
		cfg.CA = wardenCAConfig{
			Cert: "/etc/warden/mitm/ca.crt",
			Key:  "/etc/warden/mitm/ca.key",
		}
		cfg.Tenants = &wardenTenantsConfig{Dir: "/etc/warden/tenants.d/"}
	} else {
		cfg.CA = wardenCAConfig{
			Auto:       true,
			CertOutput: "/shared/warden-ca.crt",
		}
	}

	if proxy.Spec.DNS != nil {
		cfg.DNS = &wardenDNSConfig{
			DenyResolvedIPs: proxy.Spec.DNS.DenyResolvedIPs,
		}
		if proxy.Spec.DNS.Cache != nil {
			cfg.DNS.Cache = &wardenCacheConfig{
				Enabled: proxy.Spec.DNS.Cache.Enabled,
				MaxTTL:  proxy.Spec.DNS.Cache.MaxTTL,
			}
		}
	}

	if proxy.Spec.Telemetry != nil {
		cfg.Telemetry = &wardenTelemetryConfig{}
		if proxy.Spec.Telemetry.Logs != nil {
			cfg.Telemetry.Logs = &wardenLogsConfig{
				Level:  proxy.Spec.Telemetry.Logs.Level,
				Format: proxy.Spec.Telemetry.Logs.Format,
			}
		}
		if proxy.Spec.Telemetry.Traces != nil {
			cfg.Telemetry.Traces = &wardenTracesConfig{
				Enabled:  proxy.Spec.Telemetry.Traces.Enabled,
				Endpoint: proxy.Spec.Telemetry.Traces.Endpoint,
			}
		}
		if proxy.Spec.Telemetry.Metrics != nil {
			cfg.Telemetry.Metrics = &wardenMetricsConfig{
				Enabled:  proxy.Spec.Telemetry.Metrics.Enabled,
				Endpoint: proxy.Spec.Telemetry.Metrics.Endpoint,
			}
		}
	}

	return cfg
}
