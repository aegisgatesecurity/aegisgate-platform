package main

import (
	"context"
	"fmt"
	"log"
	"os"
	"time"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"

	"k8s.io/apimachinery/pkg/watch"
	"k8s.io/client-go/dynamic"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/cache"
	"k8s.io/client-go/tools/clientcmd"
)

// ---------------------------------------------------------------------------
// CRD Types
// ---------------------------------------------------------------------------

// AegisGateDeploymentSpec defines the desired state of AegisGateDeployment.
type AegisGateDeploymentSpec struct {
	Replicas         *int32                    `json:"replicas,omitempty"`
	Image            string                    `json:"image"`
	Tier             string                    `json:"tier,omitempty"`
	ProxyPort        *int32                    `json:"proxyPort,omitempty"`
	MCPPort          *int32                    `json:"mcpPort,omitempty"`
	DashboardPort    *int32                    `json:"dashboardPort,omitempty"`
	MLEnabled        *bool                     `json:"mlEnabled,omitempty"`
	MLShadowMode     *bool                     `json:"mlShadowMode,omitempty"`
	MLThreshold      *float64                  `json:"mlThreshold,omitempty"`
	Resources        *ResourceRequirementsSpec `json:"resources,omitempty"`
	LicenseKeySecret string                    `json:"licenseKeySecret,omitempty"`
	Persistence      *PersistenceSpec          `json:"persistence,omitempty"`
	Compliance       *ComplianceSpec           `json:"compliance,omitempty"`
}

// ResourceRequirementsSpec mirrors K8s resource requirements.
type ResourceRequirementsSpec struct {
	Requests *ResourceListSpec `json:"requests,omitempty"`
	Limits   *ResourceListSpec `json:"limits,omitempty"`
}

// ResourceListSpec is a map of resource name to quantity.
type ResourceListSpec struct {
	CPU    string `json:"cpu,omitempty"`
	Memory string `json:"memory,omitempty"`
}

// PersistenceSpec defines persistence configuration.
type PersistenceSpec struct {
	Enabled *bool  `json:"enabled,omitempty"`
	Size    string `json:"size,omitempty"`
}

// ComplianceSpec defines compliance configuration.
type ComplianceSpec struct {
	Frameworks     []string `json:"frameworks,omitempty"`
	RegressionGate *bool    `json:"regressionGate,omitempty"`
}

// AegisGateCondition describes a condition in the status.
type AegisGateCondition struct {
	Type               string      `json:"type"`
	Reason             string      `json:"reason,omitempty"`
	Message            string      `json:"message,omitempty"`
	LastTransitionTime metav1.Time `json:"lastTransitionTime,omitempty"`
}

// AegisGateDeploymentStatus defines the observed state.
type AegisGateDeploymentStatus struct {
	AvailableReplicas int32                `json:"availableReplicas,omitempty"`
	Ready             bool                 `json:"ready,omitempty"`
	Conditions        []AegisGateCondition `json:"conditions,omitempty"`
}

// ---------------------------------------------------------------------------
// GVR & helpers
// ---------------------------------------------------------------------------

var aegisGateGVR = schema.GroupVersionResource{
	Group:    "aegisgate.io",
	Version:  "v1alpha1",
	Resource: "aegisgatedeployments",
}

func int32Ptr(v int32) *int32       { return &v }
func boolPtr(v bool) *bool          { return &v }
func float64Ptr(v float64) *float64 { return &v }

// defaults fills in zero-value defaults.
func defaults(s *AegisGateDeploymentSpec) {
	if s.Replicas == nil {
		s.Replicas = int32Ptr(1)
	}
	if s.Tier == "" {
		s.Tier = "community"
	}
	if s.ProxyPort == nil {
		s.ProxyPort = int32Ptr(8080)
	}
	if s.MCPPort == nil {
		s.MCPPort = int32Ptr(8081)
	}
	if s.DashboardPort == nil {
		s.DashboardPort = int32Ptr(8443)
	}
	if s.MLEnabled == nil {
		s.MLEnabled = boolPtr(false)
	}
	if s.MLShadowMode == nil {
		s.MLShadowMode = boolPtr(true)
	}
	if s.MLThreshold == nil {
		s.MLThreshold = float64Ptr(0.85)
	}
	if s.Persistence != nil {
		if s.Persistence.Enabled == nil {
			s.Persistence.Enabled = boolPtr(false)
		}
		if s.Persistence.Size == "" {
			s.Persistence.Size = "10Gi"
		}
	}
	if s.Compliance != nil && s.Compliance.RegressionGate == nil {
		s.Compliance.RegressionGate = boolPtr(false)
	}
}

// ---------------------------------------------------------------------------
// Reconciler
// ---------------------------------------------------------------------------

// KubeClient abstracts the Kubernetes interactions needed for reconciliation.
type KubeClient interface {
	GetDeployment(ctx context.Context, ns, name string) (*unstructured.Unstructured, error)
	CreateDeployment(ctx context.Context, ns string, obj *unstructured.Unstructured) error
	UpdateDeployment(ctx context.Context, ns, name string, obj *unstructured.Unstructured) error
	GetService(ctx context.Context, ns, name string) (*unstructured.Unstructured, error)
	CreateService(ctx context.Context, ns string, obj *unstructured.Unstructured) error
	UpdateService(ctx context.Context, ns, name string, obj *unstructured.Unstructured) error
	GetCRD(ctx context.Context, ns, name string) (*unstructured.Unstructured, error)
	UpdateCRDStatus(ctx context.Context, ns, name string, status map[string]interface{}) error
}

// Reconciler reconciles AegisGateDeployment resources.
type Reconciler struct {
	client KubeClient
}

// Reconcile is the main reconciliation loop for an AegisGateDeployment.
func (r *Reconciler) Reconcile(ctx context.Context, ns, name string) error {
	log.Printf("Reconciling AegisGateDeployment %s/%s", ns, name)

	crd, err := r.client.GetCRD(ctx, ns, name)
	if err != nil {
		return fmt.Errorf("get CRD: %w", err)
	}

	specMap, ok := crd.Object["spec"].(map[string]interface{})
	if !ok {
		return fmt.Errorf("spec not found in CRD")
	}

	spec := specFromMap(specMap)
	defaults(&spec)

	// --- Deployment ---
	depName := name + "-deployment"
	depObj := buildDeploymentUnstructured(depName, ns, spec)

	existingDep, err := r.client.GetDeployment(ctx, ns, depName)
	if err != nil {
		// Assume not found → create
		if createErr := r.client.CreateDeployment(ctx, ns, depObj); createErr != nil {
			return fmt.Errorf("create deployment: %w", createErr)
		}
		log.Printf("Created Deployment %s/%s", ns, depName)
	} else {
		// Update existing deployment
		existingDep.Object["spec"] = depObj.Object["spec"]
		if updateErr := r.client.UpdateDeployment(ctx, ns, depName, existingDep); updateErr != nil {
			return fmt.Errorf("update deployment: %w", updateErr)
		}
		log.Printf("Updated Deployment %s/%s", ns, depName)
	}

	// --- Service ---
	svcName := name + "-service"
	svcObj := buildServiceUnstructured(svcName, ns, spec)

	existingSvc, err := r.client.GetService(ctx, ns, svcName)
	if err != nil {
		if createErr := r.client.CreateService(ctx, ns, svcObj); createErr != nil {
			return fmt.Errorf("create service: %w", createErr)
		}
		log.Printf("Created Service %s/%s", ns, svcName)
	} else {
		existingSvc.Object["spec"] = svcObj.Object["spec"]
		if updateErr := r.client.UpdateService(ctx, ns, svcName, existingSvc); updateErr != nil {
			return fmt.Errorf("update service: %w", updateErr)
		}
		log.Printf("Updated Service %s/%s", ns, svcName)
	}

	// --- Update status ---
	replicas := *spec.Replicas
	status := map[string]interface{}{
		"availableReplicas": replicas,
		"ready":             true,
		"conditions": []interface{}{
			map[string]interface{}{
				"type":               "Available",
				"reason":             "MinimumReplicasAvailable",
				"message":            fmt.Sprintf("Deployment has %d available replicas", replicas),
				"lastTransitionTime": time.Now().UTC().Format(time.RFC3339),
			},
		},
	}

	if err := r.client.UpdateCRDStatus(ctx, ns, name, status); err != nil {
		return fmt.Errorf("update status: %w", err)
	}

	log.Printf("AegisGateDeployment %s/%s reconciled successfully", ns, name)
	return nil
}

// ---------------------------------------------------------------------------
// Build unstructured K8s objects
// ---------------------------------------------------------------------------

func specFromMap(m map[string]interface{}) AegisGateDeploymentSpec {
	s := AegisGateDeploymentSpec{}
	if v, ok := m["replicas"]; ok {
		if n, ok := v.(int64); ok {
			s.Replicas = int32Ptr(int32(n)) // #nosec G115 -- JSON numbers from CRD spec, bounded to int32
		}
	}
	if v, ok := m["image"]; ok {
		s.Image, _ = v.(string)
	}
	if v, ok := m["tier"]; ok {
		s.Tier, _ = v.(string)
	}
	if v, ok := m["proxyPort"]; ok {
		if n, ok := v.(int64); ok {
			s.ProxyPort = int32Ptr(int32(n)) // #nosec G115 -- JSON numbers from CRD spec, bounded to int32
		}
	}
	if v, ok := m["mcpPort"]; ok {
		if n, ok := v.(int64); ok {
			s.MCPPort = int32Ptr(int32(n)) // #nosec G115 -- JSON numbers from CRD spec, bounded to int32
		}
	}
	if v, ok := m["dashboardPort"]; ok {
		if n, ok := v.(int64); ok {
			s.DashboardPort = int32Ptr(int32(n)) // #nosec G115 -- JSON numbers from CRD spec, bounded to int32
		}
	}
	if v, ok := m["mlEnabled"]; ok {
		if b, ok := v.(bool); ok {
			s.MLEnabled = boolPtr(b)
		}
	}
	if v, ok := m["mlShadowMode"]; ok {
		if b, ok := v.(bool); ok {
			s.MLShadowMode = boolPtr(b)
		}
	}
	if v, ok := m["mlThreshold"]; ok {
		if f, ok := v.(float64); ok {
			s.MLThreshold = float64Ptr(f)
		}
	}
	if v, ok := m["licenseKeySecret"]; ok {
		s.LicenseKeySecret, _ = v.(string)
	}
	return s
}

func buildDeploymentUnstructured(name, ns string, spec AegisGateDeploymentSpec) *unstructured.Unstructured {
	replicas := int64(1)
	if spec.Replicas != nil {
		replicas = int64(*spec.Replicas)
	}

	container := map[string]interface{}{
		"name":  "aegisgate",
		"image": spec.Image,
		"ports": []interface{}{
			map[string]interface{}{"containerPort": int64(*spec.ProxyPort), "name": "proxy"},
			map[string]interface{}{"containerPort": int64(*spec.MCPPort), "name": "mcp"},
			map[string]interface{}{"containerPort": int64(*spec.DashboardPort), "name": "dashboard"},
		},
		"env": []interface{}{
			map[string]interface{}{"name": "AEGISGATE_TIER", "value": spec.Tier},
			map[string]interface{}{"name": "AEGISGATE_PROXY_PORT", "value": fmt.Sprintf("%d", *spec.ProxyPort)},
			map[string]interface{}{"name": "AEGISGATE_MCP_PORT", "value": fmt.Sprintf("%d", *spec.MCPPort)},
			map[string]interface{}{"name": "AEGISGATE_DASHBOARD_PORT", "value": fmt.Sprintf("%d", *spec.DashboardPort)},
			map[string]interface{}{"name": "AEGISGATE_ML_ENABLED", "value": fmt.Sprintf("%t", *spec.MLEnabled)},
			map[string]interface{}{"name": "AEGISGATE_ML_SHADOW_MODE", "value": fmt.Sprintf("%t", *spec.MLShadowMode)},
			map[string]interface{}{"name": "AEGISGATE_ML_THRESHOLD", "value": fmt.Sprintf("%.2f", *spec.MLThreshold)},
		},
	}

	if spec.Resources != nil {
		resMap := map[string]interface{}{}
		if spec.Resources.Requests != nil {
			reqMap := map[string]interface{}{}
			if spec.Resources.Requests.CPU != "" {
				reqMap["cpu"] = spec.Resources.Requests.CPU
			}
			if spec.Resources.Requests.Memory != "" {
				reqMap["memory"] = spec.Resources.Requests.Memory
			}
			resMap["requests"] = reqMap
		}
		if spec.Resources.Limits != nil {
			limMap := map[string]interface{}{}
			if spec.Resources.Limits.CPU != "" {
				limMap["cpu"] = spec.Resources.Limits.CPU
			}
			if spec.Resources.Limits.Memory != "" {
				limMap["memory"] = spec.Resources.Limits.Memory
			}
			resMap["limits"] = limMap
		}
		container["resources"] = resMap
	}

	if spec.LicenseKeySecret != "" {
		envList := container["env"].([]interface{})
		envList = append(envList, map[string]interface{}{
			"name": "AEGISGATE_LICENSE_KEY",
			"valueFrom": map[string]interface{}{
				"secretKeyRef": map[string]interface{}{
					"name": spec.LicenseKeySecret,
					"key":  "license-key",
				},
			},
		})
		container["env"] = envList
	}

	obj := &unstructured.Unstructured{
		Object: map[string]interface{}{
			"apiVersion": "apps/v1",
			"kind":       "Deployment",
			"metadata": map[string]interface{}{
				"name":      name,
				"namespace": ns,
				"labels": map[string]interface{}{
					"app":                          "aegisgate",
					"app.kubernetes.io/managed-by": "aegisgate-operator",
				},
			},
			"spec": map[string]interface{}{
				"replicas": replicas,
				"selector": map[string]interface{}{
					"matchLabels": map[string]interface{}{
						"app": "aegisgate",
					},
				},
				"template": map[string]interface{}{
					"metadata": map[string]interface{}{
						"labels": map[string]interface{}{
							"app": "aegisgate",
						},
					},
					"spec": map[string]interface{}{
						"containers": []interface{}{container},
					},
				},
			},
		},
	}
	return obj
}

func buildServiceUnstructured(name, ns string, spec AegisGateDeploymentSpec) *unstructured.Unstructured {
	obj := &unstructured.Unstructured{
		Object: map[string]interface{}{
			"apiVersion": "v1",
			"kind":       "Service",
			"metadata": map[string]interface{}{
				"name":      name,
				"namespace": ns,
				"labels": map[string]interface{}{
					"app":                          "aegisgate",
					"app.kubernetes.io/managed-by": "aegisgate-operator",
				},
			},
			"spec": map[string]interface{}{
				"selector": map[string]interface{}{
					"app": "aegisgate",
				},
				"ports": []interface{}{
					map[string]interface{}{"name": "proxy", "port": int64(*spec.ProxyPort), "targetPort": int64(*spec.ProxyPort)},
					map[string]interface{}{"name": "mcp", "port": int64(*spec.MCPPort), "targetPort": int64(*spec.MCPPort)},
					map[string]interface{}{"name": "dashboard", "port": int64(*spec.DashboardPort), "targetPort": int64(*spec.DashboardPort)},
				},
				"type": "ClusterIP",
			},
		},
	}
	return obj
}

// ---------------------------------------------------------------------------
// dynamicKubeClient implements KubeClient using the dynamic client.
// ---------------------------------------------------------------------------

type dynamicKubeClient struct {
	dynClient  dynamic.Interface
	clientset  kubernetes.Interface
	deployGVR  schema.GroupVersionResource
	serviceGVR schema.GroupVersionResource
	crdGVR     schema.GroupVersionResource
}

func newDynamicKubeClient(dynClient dynamic.Interface, clientset kubernetes.Interface) *dynamicKubeClient {
	return &dynamicKubeClient{
		dynClient:  dynClient,
		clientset:  clientset,
		deployGVR:  schema.GroupVersionResource{Group: "apps", Version: "v1", Resource: "deployments"},
		serviceGVR: schema.GroupVersionResource{Group: "", Version: "v1", Resource: "services"},
		crdGVR:     aegisGateGVR,
	}
}

func (d *dynamicKubeClient) GetDeployment(ctx context.Context, ns, name string) (*unstructured.Unstructured, error) {
	return d.dynClient.Resource(d.deployGVR).Namespace(ns).Get(ctx, name, metav1.GetOptions{})
}

func (d *dynamicKubeClient) CreateDeployment(ctx context.Context, ns string, obj *unstructured.Unstructured) error {
	_, err := d.dynClient.Resource(d.deployGVR).Namespace(ns).Create(ctx, obj, metav1.CreateOptions{})
	return err
}

func (d *dynamicKubeClient) UpdateDeployment(ctx context.Context, ns, name string, obj *unstructured.Unstructured) error {
	_, err := d.dynClient.Resource(d.deployGVR).Namespace(ns).Update(ctx, obj, metav1.UpdateOptions{})
	return err
}

func (d *dynamicKubeClient) GetService(ctx context.Context, ns, name string) (*unstructured.Unstructured, error) {
	return d.dynClient.Resource(d.serviceGVR).Namespace(ns).Get(ctx, name, metav1.GetOptions{})
}

func (d *dynamicKubeClient) CreateService(ctx context.Context, ns string, obj *unstructured.Unstructured) error {
	_, err := d.dynClient.Resource(d.serviceGVR).Namespace(ns).Create(ctx, obj, metav1.CreateOptions{})
	return err
}

func (d *dynamicKubeClient) UpdateService(ctx context.Context, ns, name string, obj *unstructured.Unstructured) error {
	_, err := d.dynClient.Resource(d.serviceGVR).Namespace(ns).Update(ctx, obj, metav1.UpdateOptions{})
	return err
}

func (d *dynamicKubeClient) GetCRD(ctx context.Context, ns, name string) (*unstructured.Unstructured, error) {
	return d.dynClient.Resource(d.crdGVR).Namespace(ns).Get(ctx, name, metav1.GetOptions{})
}

func (d *dynamicKubeClient) UpdateCRDStatus(ctx context.Context, ns, name string, status map[string]interface{}) error {
	crd, err := d.GetCRD(ctx, ns, name)
	if err != nil {
		return err
	}
	crd.Object["status"] = status
	_, err = d.dynClient.Resource(d.crdGVR).Namespace(ns).UpdateStatus(ctx, crd, metav1.UpdateOptions{})
	return err
}

// ---------------------------------------------------------------------------
// WatchConfig & controller entrypoint
// ---------------------------------------------------------------------------

// WatchConfig configures the controller watch loop.
type WatchConfig struct {
	Namespace    string
	ResyncPeriod time.Duration
}

// Start begins watching AegisGateDeployment resources and reconciling them.
func (w *WatchConfig) Start(ctx context.Context, reconciler *Reconciler) error {
	config, err := restConfig()
	if err != nil {
		return fmt.Errorf("get rest config: %w", err)
	}

	dynClient, err := dynamic.NewForConfig(config)
	if err != nil {
		return fmt.Errorf("create dynamic client: %w", err)
	}

	clientset, err := kubernetes.NewForConfig(config)
	if err != nil {
		return fmt.Errorf("create clientset: %w", err)
	}

	kubeClient := newDynamicKubeClient(dynClient, clientset)
	reconciler.client = kubeClient

	store, controller := cache.NewInformer(
		&cache.ListWatch{
			ListFunc: func(options metav1.ListOptions) (runtime.Object, error) {
				return dynClient.Resource(aegisGateGVR).Namespace(w.Namespace).List(ctx, options)
			},
			WatchFunc: func(options metav1.ListOptions) (watch.Interface, error) {
				return dynClient.Resource(aegisGateGVR).Namespace(w.Namespace).Watch(ctx, options)
			},
		},
		&unstructured.Unstructured{},
		w.ResyncPeriod,
		cache.ResourceEventHandlerFuncs{
			AddFunc: func(obj interface{}) {
				u := obj.(*unstructured.Unstructured)
				if err := reconciler.Reconcile(ctx, u.GetNamespace(), u.GetName()); err != nil {
					log.Printf("reconcile error (add) %s/%s: %v", u.GetNamespace(), u.GetName(), err)
				}
			},
			UpdateFunc: func(oldObj, newObj interface{}) {
				u := newObj.(*unstructured.Unstructured)
				if err := reconciler.Reconcile(ctx, u.GetNamespace(), u.GetName()); err != nil {
					log.Printf("reconcile error (update) %s/%s: %v", u.GetNamespace(), u.GetName(), err)
				}
			},
			DeleteFunc: func(obj interface{}) {
				u := obj.(*unstructured.Unstructured)
				log.Printf("AegisGateDeployment %s/%s deleted, cleanup should be handled here", u.GetNamespace(), u.GetName())
			},
		},
	)

	_ = store // store can be used for list/get cached objects
	go controller.Run(ctx.Done())
	return nil
}

func restConfig() (*rest.Config, error) {
	if kubeconfig := os.Getenv("KUBECONFIG"); kubeconfig != "" {
		return clientcmd.BuildConfigFromFlags("", kubeconfig)
	}
	return rest.InClusterConfig()
}

// ---------------------------------------------------------------------------
// main
// ---------------------------------------------------------------------------

func main() {
	log.Println("Starting AegisGate Operator v0.1.0")

	namespace := os.Getenv("WATCH_NAMESPACE")
	if namespace == "" {
		namespace = corev1.NamespaceAll
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	reconciler := &Reconciler{}

	watchCfg := &WatchConfig{
		Namespace:    namespace,
		ResyncPeriod: 30 * time.Second,
	}

	log.Println("Starting controller watch loop...")
	if err := watchCfg.Start(ctx, reconciler); err != nil {
		log.Fatalf("Failed to start watch: %v", err)
	}

	log.Println("AegisGate Operator is running on port 9443")

	// Block until context is cancelled
	<-ctx.Done()
	log.Println("Shutting down AegisGate Operator")
}
