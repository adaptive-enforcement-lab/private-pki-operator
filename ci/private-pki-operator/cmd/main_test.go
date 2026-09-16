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

package main

import (
	"crypto/tls"
	"flag"
	"os"
	"slices"
	"testing"

	cmv1 "github.com/cert-manager/cert-manager/pkg/apis/certmanager/v1"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"sigs.k8s.io/controller-runtime/pkg/cache"
)

// withFlags runs fn against a pristine global FlagSet and restores the original
// afterwards. registerFlags binds onto flag.CommandLine, so without this every
// test after the first panics on a duplicate flag registration.
func withFlags(t *testing.T, args []string, fn func(f *operatorFlags)) {
	t.Helper()
	saved := flag.CommandLine
	t.Cleanup(func() { flag.CommandLine = saved })

	flag.CommandLine = flag.NewFlagSet(t.Name(), flag.ContinueOnError)
	flag.CommandLine.SetOutput(os.Stderr)

	f := registerFlags()
	if err := flag.CommandLine.Parse(args); err != nil {
		t.Fatalf("parsing %v: %v", args, err)
	}
	fn(f)
}

func TestRegisterFlags_Defaults(t *testing.T) {
	withFlags(t, nil, func(f *operatorFlags) {
		// The chart wires --metrics-secure=false and scrapes plain HTTP, but the
		// binary's own default stays secure: an unconfigured deployment must not
		// serve metrics in the clear.
		if !f.secureMetrics {
			t.Error("metrics-secure defaults to false; an unconfigured deployment would serve metrics in the clear")
		}
		if f.enableHTTP2 {
			t.Error("enable-http2 defaults to true; HTTP/2 is off by default for GHSA-qppj-fm5r-hxr3 / GHSA-4374-p667-p6c8")
		}
		if f.enableLeaderElection {
			t.Error("leader-elect defaults to true")
		}
		for _, tc := range []struct{ name, got, want string }{
			{"metrics-bind-address", f.metricsAddr, "0"},
			{"health-probe-bind-address", f.probeAddr, ":8081"},
			{"webhook-cert-name", f.webhookCertName, "tls.crt"},
			{"webhook-cert-key", f.webhookCertKey, "tls.key"},
			{"metrics-cert-name", f.metricsCertName, "tls.crt"},
			{"metrics-cert-key", f.metricsCertKey, "tls.key"},
		} {
			if tc.got != tc.want {
				t.Errorf("--%s = %q, want %q", tc.name, tc.got, tc.want)
			}
		}
	})
}

func TestRegisterFlags_ZapFlagsStillParse(t *testing.T) {
	// The standard controller-runtime zap flags must parse; initLogging must
	// not panic when building the logger from them.
	args := []string{
		"--zap-devel=true",
		"--zap-encoder=json",
		"--zap-log-level=debug",
		"--zap-stacktrace-level=error",
		"--zap-time-encoding=iso8601",
	}
	withFlags(t, args, func(f *operatorFlags) {
		f.initLogging() // must not panic
	})
}

func TestTLSOptions_HTTP2DisabledByDefault(t *testing.T) {
	withFlags(t, nil, func(f *operatorFlags) {
		opts := f.tlsOptions()
		if len(opts) != 1 {
			t.Fatalf("got %d TLS options, want 1 (the HTTP/2 opt-out)", len(opts))
		}
		cfg := &tls.Config{MinVersion: tls.VersionTLS12}
		opts[0](cfg)
		if !slices.Equal(cfg.NextProtos, []string{"http/1.1"}) {
			t.Errorf("NextProtos = %v, want [http/1.1]; HTTP/2 would still be negotiated", cfg.NextProtos)
		}
	})
}

func TestTLSOptions_HTTP2OptIn(t *testing.T) {
	withFlags(t, []string{"--enable-http2=true"}, func(f *operatorFlags) {
		if opts := f.tlsOptions(); len(opts) != 0 {
			t.Errorf("got %d TLS options with --enable-http2, want 0", len(opts))
		}
	})
}

func TestWebhookServer_BuildsWithAndWithoutCertDir(t *testing.T) {
	withFlags(t, nil, func(f *operatorFlags) {
		if f.webhookServer(f.tlsOptions()) == nil {
			t.Error("webhookServer returned nil with no certificate directory")
		}
	})
	withFlags(t, []string{"--webhook-cert-path=/tmp/webhook-certs"}, func(f *operatorFlags) {
		if f.webhookServer(f.tlsOptions()) == nil {
			t.Error("webhookServer returned nil with a certificate directory")
		}
	})
}

func TestMetricsOptions_SecureServingCarriesTheAuthzFilter(t *testing.T) {
	withFlags(t, []string{"--metrics-bind-address=:8443"}, func(f *operatorFlags) {
		opts := f.metricsOptions(f.tlsOptions())
		if opts.BindAddress != ":8443" {
			t.Errorf("BindAddress = %q, want :8443", opts.BindAddress)
		}
		if !opts.SecureServing {
			t.Error("SecureServing is false under the default --metrics-secure")
		}
		if opts.FilterProvider == nil {
			t.Error("FilterProvider is nil while serving securely; the endpoint would have no authn/authz")
		}
	})
}

func TestMetricsOptions_InsecureDropsTheFilter(t *testing.T) {
	// This is how the chart runs it: plain HTTP on the pod network, scraped by
	// Google Managed Prometheus, no Service in front. The authz filter would
	// require TokenReview/SubjectAccessReview RBAC the chart does not grant.
	withFlags(t, []string{"--metrics-secure=false"}, func(f *operatorFlags) {
		opts := f.metricsOptions(f.tlsOptions())
		if opts.SecureServing {
			t.Error("SecureServing stayed true under --metrics-secure=false")
		}
		if opts.FilterProvider != nil {
			t.Error("FilterProvider is set while serving plain HTTP")
		}
	})
}

func TestMetricsOptions_CertPathPopulatesTheWatcher(t *testing.T) {
	args := []string{
		"--metrics-cert-path=/tmp/metrics-certs",
		"--metrics-cert-name=custom.crt",
		"--metrics-cert-key=custom.key",
	}
	withFlags(t, args, func(f *operatorFlags) {
		opts := f.metricsOptions(f.tlsOptions())
		if opts.CertDir != "/tmp/metrics-certs" || opts.CertName != "custom.crt" || opts.KeyName != "custom.key" {
			t.Errorf("certificate watcher not wired: dir=%q name=%q key=%q",
				opts.CertDir, opts.CertName, opts.KeyName)
		}
	})
}

func TestManagerOptions_CacheRestrictionsAreNamespaceScoped(t *testing.T) {
	// The cache restrictions are load-bearing RBAC: controller-runtime defaults
	// to cluster-wide informers, and a ConfigMap or CertificateRequest informer
	// outside these namespaces would demand permissions the chart's Roles do not
	// grant. Certificates and Secrets are deliberately NOT restricted here --
	// BFS discovery reads them in any namespace.
	withFlags(t, nil, func(f *operatorFlags) {
		opts := f.managerOptions(f.tlsOptions())

		byObject := opts.Cache.ByObject
		if len(byObject) != 2 {
			t.Fatalf("cache restricts %d types, want exactly 2 (ConfigMap, CertificateRequest)", len(byObject))
		}

		var sawConfigMap, sawCertReq bool
		for obj, cfg := range byObject {
			switch obj.(type) {
			case *corev1.ConfigMap:
				sawConfigMap = true
				assertNamespaces(t, "ConfigMap", cfg.Namespaces, []string{"cert-manager"})
			case *cmv1.CertificateRequest:
				sawCertReq = true
				assertNamespaces(t, "CertificateRequest", cfg.Namespaces, []string{"cert-manager"})
			default:
				t.Errorf("unexpected type restricted in the cache: %T", obj)
			}
		}
		if !sawConfigMap {
			t.Error("ConfigMap informer is not namespace-restricted; it would need cluster-wide read")
		}
		if !sawCertReq {
			t.Error("CertificateRequest informer is not namespace-restricted")
		}
	})
}

func TestManagerOptions_ProbeAndLeaderElectionWiring(t *testing.T) {
	withFlags(t, []string{"--leader-elect=true", "--health-probe-bind-address=:9090"}, func(f *operatorFlags) {
		opts := f.managerOptions(f.tlsOptions())
		if opts.HealthProbeBindAddress != ":9090" {
			t.Errorf("HealthProbeBindAddress = %q, want :9090", opts.HealthProbeBindAddress)
		}
		if !opts.LeaderElection {
			t.Error("LeaderElection is false under --leader-elect=true")
		}
		// A changed ID silently splits the electorate: two managers would each
		// hold a different lease and both believe they are leader.
		if opts.LeaderElectionID != "8f0676ae.adaptive-enforcement-lab.com" {
			t.Errorf("LeaderElectionID = %q; changing it splits the electorate", opts.LeaderElectionID)
		}
		if opts.Scheme != scheme {
			t.Error("manager was not given the package scheme; the CRDs would not be registered")
		}
	})
}

func TestScheme_CarriesEveryTypeTheReconcilersRead(t *testing.T) {
	// init() registers these. A missing one fails at runtime on the first Get,
	// not at startup, so it is worth asserting here.
	for _, gv := range []struct {
		group, version string
	}{
		{"platform.adaptive-enforcement-lab.com", "v1alpha1"},
		{"cert-manager.io", "v1"},
		{"trust.cert-manager.io", "v1alpha1"},
		{"", "v1"},
	} {
		if !scheme.IsVersionRegistered(schemeGV(gv.group, gv.version)) {
			t.Errorf("scheme is missing group %q version %q", gv.group, gv.version)
		}
	}
}

// assertNamespaces checks a cache restriction names exactly the expected
// namespaces. The set is the permission boundary, so an extra entry is as much
// a finding as a missing one.
func assertNamespaces(t *testing.T, kind string, got map[string]cache.Config, want []string) {
	t.Helper()
	if len(got) != len(want) {
		t.Errorf("%s informer covers %d namespaces, want %d: %v", kind, len(got), len(want), keysOf(got))
		return
	}
	for _, ns := range want {
		if _, ok := got[ns]; !ok {
			t.Errorf("%s informer does not cover namespace %q; got %v", kind, ns, keysOf(got))
		}
	}
}

func keysOf(m map[string]cache.Config) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	slices.Sort(out)
	return out
}

func schemeGV(group, version string) schema.GroupVersion {
	return schema.GroupVersion{Group: group, Version: version}
}
