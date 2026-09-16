package controller

import (
	"context"
	"testing"

	cmv1 "github.com/cert-manager/cert-manager/pkg/apis/certmanager/v1"
	cmmeta "github.com/cert-manager/cert-manager/pkg/apis/meta/v1"
	"github.com/prometheus/client_golang/prometheus/testutil"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/tools/record"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"

	platformv1alpha1 "github.com/adaptive-enforcement-lab/private-pki-operator/ci/private-pki-operator/api/v1alpha1"
)

// leafReissued reads the current leaf-tier counter for a role.
func leafReissued(t *testing.T, role platformv1alpha1.PKIRotationRole) float64 {
	t.Helper()
	m, err := pkiRotationDownstreamReissuedTotal.GetMetricWithLabelValues(string(role), downstreamKindLeaf)
	if err != nil {
		t.Fatalf("reading counter: %v", err)
	}
	return testutil.ToFloat64(m)
}

// The defect in issue #268: a live rotation over 3 leaf certificates left the
// counter reading 6, because the call sat where the cascade is TRIGGERED and
// that phase can be observed more than once.
//
// This reconciles AwaitingReissuance twice — the re-entry the issue describes —
// and asserts the counter does not move on that path at all. It now advances
// only at verified completion.
func TestDownstreamReissued_ReEnteredTriggerPathDoesNotCount(t *testing.T) {
	certPEM, skid := mustGenerateTestCA(t)

	intCert := cmv1.Certificate{
		ObjectMeta: metav1.ObjectMeta{Name: "int-ca", Namespace: "cert-manager"},
		Spec: cmv1.CertificateSpec{
			SecretName: "int-ca-secret",
			IsCA:       true,
			IssuerRef:  cmmeta.IssuerReference{Name: "root-issuer", Kind: "ClusterIssuer"},
		},
		Status: cmv1.CertificateStatus{
			Conditions: []cmv1.CertificateCondition{
				{Type: cmv1.CertificateConditionReady, Status: cmmeta.ConditionTrue},
			},
		},
	}
	intSecret := corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{Name: "int-ca-secret", Namespace: "cert-manager"},
		Data:       map[string][]byte{"tls.crt": certPEM},
	}
	intIssuer := newTestClusterIssuer("int-issuer", "int-ca-secret")
	leaf := cmv1.Certificate{
		ObjectMeta: metav1.ObjectMeta{Name: "leaf", Namespace: "cert-manager"},
		Spec: cmv1.CertificateSpec{
			SecretName: "leaf-secret",
			IsCA:       false,
			IssuerRef:  cmmeta.IssuerReference{Name: "int-issuer", Kind: "ClusterIssuer"},
		},
		Status: cmv1.CertificateStatus{
			Conditions: []cmv1.CertificateCondition{
				{Type: cmv1.CertificateConditionReady, Status: cmmeta.ConditionTrue},
			},
		},
	}

	pkir := buildIntermediatePKIR()
	pkir.Status.Phase = platformv1alpha1.PhaseAwaitingReissuance
	pkir.Status.CurrentSKID = skid

	c := fake.NewClientBuilder().
		WithScheme(makeCMScheme()).
		WithObjects(&intCert, &intSecret, &intIssuer, &leaf, pkir).
		WithStatusSubresource(pkir, &leaf).
		Build()
	r := &PKIRotationReconciler{Client: c, Scheme: makeCMScheme(), Recorder: record.NewFakeRecorder(20)}

	before := leafReissued(t, platformv1alpha1.RoleIntermediateCA)

	for pass := 1; pass <= 2; pass++ {
		pkir.Status.Phase = platformv1alpha1.PhaseAwaitingReissuance
		if _, err := r.reconcileAwaitingReissuanceIntermediate(context.Background(), pkir); err != nil {
			t.Fatalf("pass %d: unexpected error: %v", pass, err)
		}
	}

	if got := leafReissued(t, platformv1alpha1.RoleIntermediateCA) - before; got != 0 {
		t.Errorf("counter advanced by %v across two AwaitingReissuance passes; the trigger path must not count", got)
	}
}

// At verified completion the counter advances by exactly the cascade size, once.
func TestDownstreamReissued_CountsVerifiedCascadeExactlyOnce(t *testing.T) {
	role := platformv1alpha1.RoleIntermediateCA
	before := leafReissued(t, role)

	pkir := buildIntermediatePKIR()
	recordDownstreamReissued(pkir, 0, 3)

	if got := leafReissued(t, role) - before; got != 3 {
		t.Errorf("counter advanced by %v for a 3-leaf cascade, want 3", got)
	}
}

// Two separate rotations accumulate; the counter is cumulative by design and
// must not be reset or overwritten per rotation.
func TestDownstreamReissued_AccumulatesAcrossRotations(t *testing.T) {
	role := platformv1alpha1.RoleIntermediateCA
	before := leafReissued(t, role)

	pkir := buildIntermediatePKIR()
	recordDownstreamReissued(pkir, 0, 2)
	recordDownstreamReissued(pkir, 0, 4)

	if got := leafReissued(t, role) - before; got != 6 {
		t.Errorf("counter advanced by %v across two cascades of 2 and 4, want 6", got)
	}
}

// A cascade that touched nothing must not create a spurious increment — the
// zero-valued series already exists from pre-initialisation.
func TestDownstreamReissued_EmptyCascadeDoesNotIncrement(t *testing.T) {
	role := platformv1alpha1.RoleRootCA
	before := leafReissued(t, role)

	recordDownstreamReissued(&platformv1alpha1.PKIRotation{
		Spec: platformv1alpha1.PKIRotationSpec{Role: role},
	}, 0, 0)

	if got := leafReissued(t, role); got != before {
		t.Errorf("counter moved by %v for an empty cascade, want 0", got-before)
	}
}
