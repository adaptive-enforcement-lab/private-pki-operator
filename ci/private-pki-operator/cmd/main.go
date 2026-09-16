/*
Copyright 2026.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

// Package main is the entrypoint for the private-pki-operator manager binary.
// It wires the scheme, the namespace-scoped cache and the PKIRotation
// reconciler onto a controller-runtime manager.
package main

import (
	"crypto/tls"
	"flag"
	"os"

	// Import all Kubernetes client auth plugins (e.g. Azure, GCP, OIDC, etc.)
	// to ensure that exec-entrypoint and run can make use of them.
	_ "k8s.io/client-go/plugin/pkg/client/auth"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/runtime"
	utilruntime "k8s.io/apimachinery/pkg/util/runtime"
	clientgoscheme "k8s.io/client-go/kubernetes/scheme"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/cache"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/healthz"
	"sigs.k8s.io/controller-runtime/pkg/log/zap"
	"sigs.k8s.io/controller-runtime/pkg/metrics"
	"sigs.k8s.io/controller-runtime/pkg/metrics/filters"
	metricsserver "sigs.k8s.io/controller-runtime/pkg/metrics/server"
	"sigs.k8s.io/controller-runtime/pkg/webhook"

	platformv1alpha1 "github.com/adaptive-enforcement-lab/private-pki-operator/ci/private-pki-operator/api/v1alpha1"
	"github.com/adaptive-enforcement-lab/private-pki-operator/ci/private-pki-operator/internal/controller"
	cmv1 "github.com/cert-manager/cert-manager/pkg/apis/certmanager/v1"
	trustv1alpha1 "github.com/cert-manager/trust-manager/pkg/apis/trust/v1alpha1"
	// +kubebuilder:scaffold:imports
)

var (
	scheme   = runtime.NewScheme()
	setupLog = ctrl.Log.WithName("setup")
)

func init() {
	utilruntime.Must(clientgoscheme.AddToScheme(scheme))

	utilruntime.Must(platformv1alpha1.AddToScheme(scheme))
	utilruntime.Must(cmv1.AddToScheme(scheme))
	utilruntime.Must(trustv1alpha1.AddToScheme(scheme))
	// +kubebuilder:scaffold:scheme
}

// operatorFlags is the manager binary's whole command-line surface. Values are
// only meaningful after flag.Parse.
type operatorFlags struct {
	metricsAddr     string
	probeAddr       string
	metricsCertPath string
	metricsCertName string
	metricsCertKey  string
	webhookCertPath string
	webhookCertName string
	webhookCertKey  string

	enableLeaderElection bool
	secureMetrics        bool
	enableHTTP2          bool

	zapOptions zap.Options
}

// registerFlags binds every flag onto a fresh operatorFlags. The caller must
// still call flag.Parse.
func registerFlags() *operatorFlags {
	f := &operatorFlags{}

	flag.StringVar(&f.metricsAddr, "metrics-bind-address", "0",
		"The address the metrics endpoint binds to. "+
			"Use :8443 for HTTPS or :8080 for HTTP, or leave as 0 to disable the metrics service.")
	flag.StringVar(&f.probeAddr, "health-probe-bind-address", ":8081",
		"The address the probe endpoint binds to.")
	flag.BoolVar(&f.enableLeaderElection, "leader-elect", false,
		"Enable leader election for controller manager. "+
			"Enabling this will ensure there is only one active controller manager.")
	flag.BoolVar(&f.secureMetrics, "metrics-secure", true,
		"If set, the metrics endpoint is served securely via HTTPS. "+
			"Use --metrics-secure=false to use HTTP instead.")
	flag.StringVar(&f.webhookCertPath, "webhook-cert-path", "",
		"The directory that contains the webhook certificate.")
	flag.StringVar(&f.webhookCertName, "webhook-cert-name", "tls.crt",
		"The name of the webhook certificate file.")
	flag.StringVar(&f.webhookCertKey, "webhook-cert-key", "tls.key",
		"The name of the webhook key file.")
	flag.StringVar(&f.metricsCertPath, "metrics-cert-path", "",
		"The directory that contains the metrics server certificate.")
	flag.StringVar(&f.metricsCertName, "metrics-cert-name", "tls.crt",
		"The name of the metrics server certificate file.")
	flag.StringVar(&f.metricsCertKey, "metrics-cert-key", "tls.key",
		"The name of the metrics server key file.")
	flag.BoolVar(&f.enableHTTP2, "enable-http2", false,
		"If set, HTTP/2 will be enabled for the metrics and webhook servers")

	f.zapOptions.BindFlags(flag.CommandLine)

	return f
}

// initLogging installs the process-wide logger built from the standard
// controller-runtime zap flags (--zap-devel, --zap-log-level, etc).
func (f *operatorFlags) initLogging() {
	ctrl.SetLogger(zap.New(zap.UseFlagOptions(&f.zapOptions)))
}

// tlsOptions disables HTTP/2 unless --enable-http2 was passed. HTTP/2 is off by
// default because of the Stream Cancellation and Rapid Reset CVEs:
//   - https://github.com/advisories/GHSA-qppj-fm5r-hxr3
//   - https://github.com/advisories/GHSA-4374-p667-p6c8
func (f *operatorFlags) tlsOptions() []func(*tls.Config) {
	if f.enableHTTP2 {
		return nil
	}
	return []func(*tls.Config){func(c *tls.Config) {
		setupLog.Info("Disabling HTTP/2")
		c.NextProtos = []string{"http/1.1"}
	}}
}

// webhookServer builds the webhook server, serving the supplied certificate
// directory when one was configured.
func (f *operatorFlags) webhookServer(tlsOpts []func(*tls.Config)) webhook.Server {
	opts := webhook.Options{TLSOpts: tlsOpts}
	if len(f.webhookCertPath) > 0 {
		setupLog.Info("Initializing webhook certificate watcher using provided certificates",
			"webhook-cert-path", f.webhookCertPath,
			"webhook-cert-name", f.webhookCertName,
			"webhook-cert-key", f.webhookCertKey)
		opts.CertDir = f.webhookCertPath
		opts.CertName = f.webhookCertName
		opts.KeyName = f.webhookCertKey
	}
	return webhook.NewServer(opts)
}

// metricsOptions configures the metrics server. More info:
//   - https://pkg.go.dev/sigs.k8s.io/controller-runtime@v0.23.1/pkg/metrics/server
//   - https://book.kubebuilder.io/reference/metrics.html
//
// If no certificate is specified, controller-runtime would generate a
// self-signed one. This operator does not take that route: the metrics endpoint
// is served over plain HTTP on the pod network and scraped by Prometheus via
// a PodMonitor, with no Service in front of it, and the chart wires
// --metrics-secure=false to match. Terminating TLS here would
// additionally require TokenReview/SubjectAccessReview RBAC and scrape-side
// trust, which the chart deliberately does not set up. The kustomize overlays
// the kubebuilder scaffold pointed at ([METRICS-WITH-CERTS],
// [PROMETHEUS-WITH-CERTS]) are not used by this repo — deployment is by Helm
// chart, not kustomize.
func (f *operatorFlags) metricsOptions(tlsOpts []func(*tls.Config)) metricsserver.Options {
	opts := metricsserver.Options{
		BindAddress:   f.metricsAddr,
		SecureServing: f.secureMetrics,
		TLSOpts:       tlsOpts,
	}
	if f.secureMetrics {
		// FilterProvider protects the metrics endpoint with authn/authz so only
		// authorized users and service accounts reach it. The RBAC is configured
		// in 'config/rbac/kustomization.yaml'. More info:
		// https://pkg.go.dev/sigs.k8s.io/controller-runtime@v0.23.1/pkg/metrics/filters#WithAuthenticationAndAuthorization
		opts.FilterProvider = filters.WithAuthenticationAndAuthorization
	}
	if len(f.metricsCertPath) > 0 {
		setupLog.Info("Initializing metrics certificate watcher using provided certificates",
			"metrics-cert-path", f.metricsCertPath,
			"metrics-cert-name", f.metricsCertName,
			"metrics-cert-key", f.metricsCertKey)
		opts.CertDir = f.metricsCertPath
		opts.CertName = f.metricsCertName
		opts.KeyName = f.metricsCertKey
	}
	return opts
}

// managerOptions assembles the controller-runtime manager configuration.
//
// Per-type cache restrictions. Cluster-scoped types (PKIRotation,
// ClusterIssuer, Bundle) are always watched cluster-wide by controller-runtime
// regardless of this setting.
//
// Certificates and Secrets are watched cluster-wide: the BFS discovery finds
// intermediate CA Secrets and Certificates in any namespace (security,
// chaos-mesh, rabbitmq, platform, …). The Secret watch triggers
// independent-intermediate-rotation detection regardless of which namespace the
// intermediate CA lives in.
//
// CertificateRequests are restricted to cert-manager (root CA rotation
// detection only needs cert-manager CertificateRequests). ConfigMaps are
// restricted to cert-manager and security (trust-manager Bundle output).
func (f *operatorFlags) managerOptions(tlsOpts []func(*tls.Config)) ctrl.Options {
	return ctrl.Options{
		Scheme:  scheme,
		Metrics: f.metricsOptions(tlsOpts),
		Cache: cache.Options{
			ByObject: map[client.Object]cache.ByObject{
				&corev1.ConfigMap{}: {
					Namespaces: map[string]cache.Config{
						"cert-manager": {},
						"security":     {},
					},
				},
				&cmv1.CertificateRequest{}: {
					Namespaces: map[string]cache.Config{"cert-manager": {}},
				},
			},
		},
		WebhookServer:          f.webhookServer(tlsOpts),
		HealthProbeBindAddress: f.probeAddr,
		LeaderElection:         f.enableLeaderElection,
		LeaderElectionID:       "8f0676ae.adaptive-enforcement-lab.com",
		// LeaderElectionReleaseOnCancel defines if the leader should step down voluntarily
		// when the Manager ends. This requires the binary to immediately end when the
		// Manager is stopped, otherwise, this setting is unsafe. Setting this significantly
		// speeds up voluntary leader transitions as the new leader don't have to wait
		// LeaseDuration time first.
		//
		// In the default scaffold provided, the program ends immediately after
		// the manager stops, so would be fine to enable this option. However,
		// if you are doing or is intended to do any operation such as perform cleanups
		// after the manager stops then its usage might be unsafe.
		// LeaderElectionReleaseOnCancel: true,
	}
}

func main() {
	flags := registerFlags()
	flag.Parse()
	flags.initLogging()

	tlsOpts := flags.tlsOptions()

	mgr, err := ctrl.NewManager(ctrl.GetConfigOrDie(), flags.managerOptions(tlsOpts))
	if err != nil {
		setupLog.Error(err, "Failed to start manager")
		os.Exit(1)
	}

	if err := (&controller.PKIRotationReconciler{
		Client: mgr.GetClient(),
		// GetAPIReader bypasses the cache for Secret reads in namespaces outside
		// cert-manager (intermediate CA Secrets in chaos-mesh, security, etc.).
		Reader:   mgr.GetAPIReader(),
		Scheme:   mgr.GetScheme(),
		Recorder: mgr.GetEventRecorderFor("pkirotation-controller"), //nolint:staticcheck
	}).SetupWithManager(mgr); err != nil {
		setupLog.Error(err, "Failed to create controller", "controller", "PKIRotation")
		os.Exit(1)
	}
	ctx := ctrl.SetupSignalHandler()
	// +kubebuilder:scaffold:builder

	// Fleet counts are read from the manager's cache at scrape time, so this must
	// be registered after the manager exists and before it starts serving metrics.
	metrics.Registry.MustRegister(controller.NewFleetCollector(mgr.GetCache()))

	if err := mgr.AddHealthzCheck("healthz", healthz.Ping); err != nil {
		setupLog.Error(err, "Failed to set up health check")
		os.Exit(1)
	}
	if err := mgr.AddReadyzCheck("readyz", healthz.Ping); err != nil {
		setupLog.Error(err, "Failed to set up ready check")
		os.Exit(1)
	}

	setupLog.Info("Starting manager")
	if err := mgr.Start(ctx); err != nil {
		setupLog.Error(err, "Failed to run manager")
		os.Exit(1)
	}
}
