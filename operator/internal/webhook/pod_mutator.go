package webhook

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/resource"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/log"
	"sigs.k8s.io/controller-runtime/pkg/webhook/admission"

	wardenio "github.com/rsturla/warden/operator/api/v1alpha1"
)

const (
	labelInject = "wardenproxy.dev/inject"
	labelTenant = "wardenproxy.dev/tenant"
	bridgeName  = "warden-bridge"
	certVolName = "warden-client-cert"
	certMount   = "/etc/warden-certs"
)

type PodMutator struct {
	Client  client.Client
	Decoder admission.Decoder
}

func (m *PodMutator) Handle(ctx context.Context, req admission.Request) admission.Response {
	logger := log.FromContext(ctx)

	pod := &corev1.Pod{}
	if err := m.Decoder.Decode(req, pod); err != nil {
		return admission.Errored(http.StatusBadRequest, err)
	}

	inject := pod.Labels[labelInject]
	if inject != "true" {
		return admission.Allowed("no injection requested")
	}

	tenantName := pod.Labels[labelTenant]
	if tenantName == "" {
		return admission.Denied("wardenproxy.dev/tenant label required when wardenproxy.dev/inject=true")
	}

	if hasBridgeContainer(pod) {
		return admission.Allowed("bridge already injected")
	}

	proxy, err := m.findWardenProxy(ctx, req.Namespace)
	if err != nil {
		logger.Error(err, "no WardenProxy found")
		return admission.Errored(http.StatusInternalServerError, err)
	}

	if proxy.Spec.MultiTenant == nil {
		return admission.Denied("WardenProxy does not have multiTenant enabled")
	}

	certSecretName := "warden-tenant-" + tenantName + "-cert"
	proxyAddr := fmt.Sprintf("%s.%s.svc:%d", proxy.Name, proxy.Namespace, proxyPort(proxy))

	bridgeResources := proxy.Spec.MultiTenant.BridgeResources
	if len(bridgeResources.Requests) == 0 {
		bridgeResources.Requests = corev1.ResourceList{
			corev1.ResourceCPU:    resource.MustParse("10m"),
			corev1.ResourceMemory: resource.MustParse("16Mi"),
		}
	}
	if len(bridgeResources.Limits) == 0 {
		bridgeResources.Limits = corev1.ResourceList{
			corev1.ResourceCPU:    resource.MustParse("100m"),
			corev1.ResourceMemory: resource.MustParse("32Mi"),
		}
	}

	pod.Spec.Volumes = append(pod.Spec.Volumes, corev1.Volume{
		Name: certVolName,
		VolumeSource: corev1.VolumeSource{
			Secret: &corev1.SecretVolumeSource{SecretName: certSecretName},
		},
	})

	pod.Spec.Containers = append(pod.Spec.Containers, corev1.Container{
		Name:    bridgeName,
		Image:   proxy.Spec.Image,
		Command: []string{"warden-bridge"},
		Args: []string{
			"--listen=127.0.0.1:8080",
			"--proxy-addr=" + proxyAddr,
			"--client-cert=" + certMount + "/tls.crt",
			"--client-key=" + certMount + "/tls.key",
			"--proxy-ca=" + certMount + "/ca.crt",
		},
		VolumeMounts: []corev1.VolumeMount{
			{Name: certVolName, MountPath: certMount, ReadOnly: true},
		},
		Resources: bridgeResources,
	})

	for i := range pod.Spec.Containers {
		if pod.Spec.Containers[i].Name == bridgeName {
			continue
		}
		pod.Spec.Containers[i].Env = appendEnvIfMissing(pod.Spec.Containers[i].Env, "HTTP_PROXY", "http://127.0.0.1:8080")
		pod.Spec.Containers[i].Env = appendEnvIfMissing(pod.Spec.Containers[i].Env, "HTTPS_PROXY", "http://127.0.0.1:8080")
	}

	if pod.Labels == nil {
		pod.Labels = make(map[string]string)
	}
	pod.Labels["role"] = "agent"

	marshaledPod, err := json.Marshal(pod)
	if err != nil {
		return admission.Errored(http.StatusInternalServerError, err)
	}
	return admission.PatchResponseFromRaw(req.Object.Raw, marshaledPod)
}

func (m *PodMutator) findWardenProxy(ctx context.Context, namespace string) (*wardenio.WardenProxy, error) {
	var list wardenio.WardenProxyList
	if err := m.Client.List(ctx, &list, client.InNamespace(namespace)); err != nil {
		return nil, fmt.Errorf("listing WardenProxy: %w", err)
	}
	if len(list.Items) == 0 {
		return nil, fmt.Errorf("no WardenProxy in namespace %s", namespace)
	}
	return &list.Items[0], nil
}

func hasBridgeContainer(pod *corev1.Pod) bool {
	for _, c := range pod.Spec.Containers {
		if c.Name == bridgeName {
			return true
		}
	}
	return false
}

func appendEnvIfMissing(envs []corev1.EnvVar, name, value string) []corev1.EnvVar {
	for _, e := range envs {
		if e.Name == name {
			return envs
		}
	}
	return append(envs, corev1.EnvVar{Name: name, Value: value})
}

func proxyPort(proxy *wardenio.WardenProxy) int32 {
	if proxy.Spec.MultiTenant != nil {
		return 8443
	}
	return 8080
}
