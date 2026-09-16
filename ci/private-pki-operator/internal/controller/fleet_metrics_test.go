package controller

import (
	"context"
	"errors"
	"strings"
	"testing"

	cmv1 "github.com/cert-manager/cert-manager/pkg/apis/certmanager/v1"
	cmmeta "github.com/cert-manager/cert-manager/pkg/apis/meta/v1"
	"github.com/prometheus/client_golang/prometheus"
	dto "github.com/prometheus/client_model/go"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
	"sigs.k8s.io/controller-runtime/pkg/client/interceptor"

	platformv1alpha1 "github.com/adaptive-enforcement-lab/private-pki-operator/ci/private-pki-operator/api/v1alpha1"
)

// errCertListFailed simulates an unavailable cache read.
var errCertListFailed = errors.New("simulated cache read failure")

// collected is one emitted sample reduced to the fields the assertions care about.
type collected struct {
	name   string
	labels map[string]string
	value  float64
}

// collectAll drains a FleetCollector into a comparable form.
func collectAll(t *testing.T, c *FleetCollector) []collected {
	t.Helper()
	ch := make(chan prometheus.Metric, 64)
	c.Collect(ch)
	close(ch)

	var out []collected
	for m := range ch {
		var pb dto.Metric
		if err := m.Write(&pb); err != nil {
			t.Fatalf("writing metric: %v", err)
		}
		labels := map[string]string{}
		for _, lp := range pb.GetLabel() {
			labels[lp.GetName()] = lp.GetValue()
		}
		out = append(out, collected{
			name:   descName(m.Desc().String()),
			labels: labels,
			value:  pb.GetGauge().GetValue(),
		})
	}
	return out
}

// find returns the value of the sample matching name and the given label subset.
// The second return reports whether such a sample was emitted at all — the
// distinction the "absent series is the honest signal" contract rests on.
func find(samples []collected, name string, labels map[string]string) (float64, bool) {
	for _, s := range samples {
		if s.name != name {
			continue
		}
		match := true
		for k, v := range labels {
			if s.labels[k] != v {
				match = false
				break
			}
		}
		if match {
			return s.value, true
		}
	}
	return 0, false
}

// caCert builds a Ready CA Certificate. CA certs are Ready in every fixture
// here; the not-Ready case is exercised on a leaf, where it is the interesting
// one — a broken leaf must not reduce the intermediate count.
func fixtureCACert(name, namespace string) *cmv1.Certificate {
	return fixtureCert(name, namespace, true, true)
}

// leafCert builds a non-CA Certificate.
func fixtureLeafCert(name, namespace string, ready bool) *cmv1.Certificate {
	return fixtureCert(name, namespace, false, ready)
}

func fixtureCert(name, namespace string, isCA, ready bool) *cmv1.Certificate {
	status := cmmeta.ConditionFalse
	if ready {
		status = cmmeta.ConditionTrue
	}
	return &cmv1.Certificate{
		ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: namespace},
		Spec:       cmv1.CertificateSpec{SecretName: name + "-secret", IsCA: isCA},
		Status: cmv1.CertificateStatus{
			Conditions: []cmv1.CertificateCondition{{Type: cmv1.CertificateConditionReady, Status: status}},
		},
	}
}

// rootRotation names a root CA certificate, which is what promotes that
// certificate to tier=root. The namespace is fixed at cert-manager, which is
// where the platform root CA lives by definition.
func rootRotation(name, certName string) *platformv1alpha1.PKIRotation {
	const certNamespace = "cert-manager"
	return &platformv1alpha1.PKIRotation{
		ObjectMeta: metav1.ObjectMeta{Name: name},
		Spec: platformv1alpha1.PKIRotationSpec{
			Role:   platformv1alpha1.RoleRootCA,
			RootCA: platformv1alpha1.RootCARef{CertificateName: certName, CertificateNamespace: certNamespace},
		},
	}
}

// fleetFixture mirrors the shape of a real cluster: one root, two intermediates
// in different namespaces, three leaves, one of which is not Ready.
func fleetFixture() []client.Object {
	return []client.Object{
		rootRotation("platform-root-ca", "private-root-ca"),
		buildIntermediatePKIR(),
		fixtureCACert("private-root-ca", "cert-manager"),
		fixtureCACert("private-intermediate-ca", "cert-manager"),
		fixtureCACert("rabbitmq-intermediate-ca", "rabbitmq"),
		fixtureLeafCert("app-tls", "cert-manager", true),
		fixtureLeafCert("rabbitmq-server", "rabbitmq", true),
		fixtureLeafCert("broken-tls", "security", false),
	}
}

func TestFleetCollector_TiersCertificatesByDeclaredRoot(t *testing.T) {
	c := fake.NewClientBuilder().WithScheme(makeCMScheme()).WithObjects(fleetFixture()...).Build()
	samples := collectAll(t, NewFleetCollector(c))

	for _, tc := range []struct {
		tier string
		want float64
	}{
		{certTierRoot, 1},         // only the cert a PKIRotation names as spec.rootCA
		{certTierIntermediate, 2}, // the other two isCA certs
		{certTierLeaf, 3},
	} {
		got, ok := find(samples, metricPrefix+"certificates", map[string]string{"tier": tc.tier})
		if !ok {
			t.Errorf("tier %q: no series emitted", tc.tier)
			continue
		}
		if got != tc.want {
			t.Errorf("certificates{tier=%q} = %v, want %v", tc.tier, got, tc.want)
		}
	}
}

// A CA certificate is only a root because a rotation declares it one. Without
// that declaration it is an ordinary intermediate — the property that keeps the
// count aligned with what the operator manages rather than with cert-manager's
// whole inventory.
func TestFleetCollector_RootRequiresARotationDeclaringIt(t *testing.T) {
	objs := []client.Object{
		fixtureCACert("private-root-ca", "cert-manager"),
		fixtureLeafCert("app-tls", "cert-manager", true),
	}
	c := fake.NewClientBuilder().WithScheme(makeCMScheme()).WithObjects(objs...).Build()
	samples := collectAll(t, NewFleetCollector(c))

	if got, _ := find(samples, metricPrefix+"certificates", map[string]string{"tier": certTierRoot}); got != 0 {
		t.Errorf("certificates{tier=root} = %v with no rotation declaring one, want 0", got)
	}
	if got, _ := find(samples, metricPrefix+"certificates", map[string]string{"tier": certTierIntermediate}); got != 1 {
		t.Errorf("certificates{tier=intermediate} = %v, want 1 — an undeclared CA cert is an intermediate", got)
	}
}

func TestFleetCollector_ReadyCountsOnlyReadyCertificates(t *testing.T) {
	c := fake.NewClientBuilder().WithScheme(makeCMScheme()).WithObjects(fleetFixture()...).Build()
	samples := collectAll(t, NewFleetCollector(c))

	total, _ := find(samples, metricPrefix+"certificates", map[string]string{"tier": certTierLeaf})
	ready, ok := find(samples, metricPrefix+"certificates_ready", map[string]string{"tier": certTierLeaf})
	if !ok {
		t.Fatal("no certificates_ready series for tier=leaf")
	}
	if total != 3 || ready != 2 {
		t.Errorf(
			"leaf total=%v ready=%v, want 3 and 2 — the not-Ready cert must be excluded from ready only", total,
			ready,
		)
	}
}

func TestFleetCollector_NamespacesAreDistinct(t *testing.T) {
	c := fake.NewClientBuilder().WithScheme(makeCMScheme()).WithObjects(fleetFixture()...).Build()
	samples := collectAll(t, NewFleetCollector(c))

	// cert-manager, rabbitmq, security — three distinct, from six certificates.
	got, ok := find(samples, metricPrefix+"namespaces", nil)
	if !ok {
		t.Fatal("no namespaces series emitted")
	}
	if got != 3 {
		t.Errorf("namespaces = %v, want 3 distinct", got)
	}
}

func TestFleetCollector_RotationsByRole(t *testing.T) {
	c := fake.NewClientBuilder().WithScheme(makeCMScheme()).WithObjects(fleetFixture()...).Build()
	samples := collectAll(t, NewFleetCollector(c))

	root, _ := find(samples, metricPrefix+"rotations", map[string]string{"role": string(platformv1alpha1.RoleRootCA)})
	inter, _ := find(
		samples, metricPrefix+"rotations", map[string]string{"role": string(platformv1alpha1.RoleIntermediateCA)},
	)
	if root != 1 || inter != 1 {
		t.Errorf("rotations root=%v intermediate=%v, want 1 and 1", root, inter)
	}
}

// Both roles must be emitted even when the estate has none of one, so a panel
// reads "0" rather than "no data".
func TestFleetCollector_EmitsBothRolesWhenOneIsAbsent(t *testing.T) {
	c := fake.NewClientBuilder().WithScheme(makeCMScheme()).
		WithObjects(rootRotation("platform-root-ca", "private-root-ca")).Build()
	samples := collectAll(t, NewFleetCollector(c))

	intermediateLabels := map[string]string{"role": string(platformv1alpha1.RoleIntermediateCA)}
	if _, ok := find(samples, metricPrefix+"rotations", intermediateLabels); !ok {
		t.Error("no rotations series for IntermediateCA; a zero must be emitted, not omitted")
	}
}

// The contract that matters most: a failed List DROPS the series rather than
// reporting zero. Zero means "this hierarchy is empty", which for a read failure
// is the one answer that must never be given.
func TestFleetCollector_FailedCertificateListEmitsNoCertificateSeries(t *testing.T) {
	c := fake.NewClientBuilder().WithScheme(makeCMScheme()).WithObjects(fleetFixture()...).
		WithInterceptorFuncs(interceptor.Funcs{
			List: func(ctx context.Context, cl client.WithWatch, list client.ObjectList, opts ...client.ListOption) error {
				if _, isCerts := list.(*cmv1.CertificateList); isCerts {
					return errCertListFailed
				}
				return cl.List(ctx, list, opts...)
			},
		}).Build()

	samples := collectAll(t, NewFleetCollector(c))

	if _, ok := find(samples, metricPrefix+"certificates", map[string]string{"tier": certTierLeaf}); ok {
		t.Error("certificates series emitted despite a failed List; an absent series is the honest signal")
	}
	if _, ok := find(samples, metricPrefix+"namespaces", nil); ok {
		t.Error("namespaces series emitted despite a failed List")
	}
	// The rotation list succeeded, so its series must still be reported.
	rootLabels := map[string]string{"role": string(platformv1alpha1.RoleRootCA)}
	if _, ok := find(samples, metricPrefix+"rotations", rootLabels); !ok {
		t.Error("rotations series dropped even though its own List succeeded")
	}
}

func TestFleetCollector_DescribeAnnouncesEveryMetric(t *testing.T) {
	ch := make(chan *prometheus.Desc, 16)
	NewFleetCollector(fake.NewClientBuilder().WithScheme(makeCMScheme()).Build()).Describe(ch)
	close(ch)

	n := 0
	for range ch {
		n++
	}
	if n != 4 {
		t.Errorf(
			"Describe announced %d descriptors, want 4 (certificates, certificates_ready, namespaces, rotations)", n,
		)
	}
}

func TestRootCertificateRefs_CollapsesDuplicatesAndSkipsUnnamed(t *testing.T) {
	list := &platformv1alpha1.PKIRotationList{Items: []platformv1alpha1.PKIRotation{
		*rootRotation("a", "private-root-ca"),
		*rootRotation("b", "private-root-ca"), // same cert, two rotations
		*rootRotation("c", ""),                // unnamed, must be skipped
	}}
	got := rootCertificateRefs(list)
	if len(got) != 1 {
		t.Errorf(
			"rootCertificateRefs returned %d refs, want 1 (duplicates collapse, unnamed skipped): %v", len(got), got,
		)
	}
	if !got[certRef{name: "private-root-ca", namespace: "cert-manager"}] {
		t.Error("expected the named root cert to be present")
	}
}

func TestRootCertificateRefs_NilListIsEmpty(t *testing.T) {
	if got := rootCertificateRefs(nil); len(got) != 0 {
		t.Errorf("rootCertificateRefs(nil) = %v, want empty", got)
	}
}

// descName pulls the fqName out of a Desc's String() form, which is the only
// exported way to recover it from a const metric.
func descName(desc string) string {
	_, rest, found := strings.Cut(desc, `fqName: "`)
	if !found {
		return ""
	}
	name, _, found := strings.Cut(rest, `"`)
	if !found {
		return ""
	}
	return name
}
