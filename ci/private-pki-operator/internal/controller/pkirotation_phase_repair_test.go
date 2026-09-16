package controller

import (
	"context"
	"testing"

	cmv1 "github.com/cert-manager/cert-manager/pkg/apis/certmanager/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/tools/record"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"

	platformv1alpha1 "github.com/adaptive-enforcement-lab/private-pki-operator/ci/private-pki-operator/api/v1alpha1"
)

// intermediateFixture builds the CA Certificate, its backing Secret and a
// reconciler wired to a fake client holding all three, for the phase-repair
// tests below.
func intermediateFixture(t *testing.T, pkir *platformv1alpha1.PKIRotation, certPEM []byte) *PKIRotationReconciler {
	t.Helper()
	cert := cmv1.Certificate{
		ObjectMeta: metav1.ObjectMeta{Name: "int-ca", Namespace: "cert-manager"},
		Spec:       cmv1.CertificateSpec{SecretName: "int-ca-secret", IsCA: true},
	}
	secret := corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{Name: "int-ca-secret", Namespace: "cert-manager"},
		Data:       map[string][]byte{"tls.crt": certPEM},
	}
	c := fake.NewClientBuilder().
		WithScheme(makeCMScheme()).
		WithObjects(&cert, &secret, pkir).
		WithStatusSubresource(pkir).
		Build()
	return &PKIRotationReconciler{Client: c, Scheme: makeCMScheme(), Recorder: record.NewFakeRecorder(10)}
}

// The exact state observed in STG, PRD and OPS for four weeks (issue #259): the
// SKID was recorded but the phase never was, so the SKID-unchanged early return
// fired on every reconcile and nothing ever wrote a phase.
func TestReconcileIdleIntermediate_NormalisesEmptyPhaseWhenSKIDUnchanged(t *testing.T) {
	certPEM, skid := mustGenerateTestCA(t)

	pkir := buildIntermediatePKIR()
	pkir.Status.Phase = "" // never written
	pkir.Status.CurrentSKID = skid

	r := intermediateFixture(t, pkir, certPEM)

	if _, err := r.reconcileIdleIntermediate(context.Background(), pkir); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	var got platformv1alpha1.PKIRotation
	if err := r.Get(context.Background(), types.NamespacedName{Name: pkir.Name}, &got); err != nil {
		t.Fatalf("reading back: %v", err)
	}
	if got.Status.Phase != platformv1alpha1.PhaseIdle {
		t.Errorf(
			"phase = %q, want %q — an empty phase must be repaired, not left", got.Status.Phase,
			platformv1alpha1.PhaseIdle,
		)
	}
	if got.Status.CurrentSKID != skid {
		t.Errorf(
			"currentSKID = %q, want %q — the repair must not disturb the recorded SKID", got.Status.CurrentSKID, skid,
		)
	}
}

// The repair must be a no-op once the phase is valid: rewriting status on every
// reconcile of a settled CR would generate needless API traffic and resourceVersion churn.
func TestReconcileIdleIntermediate_LeavesValidPhaseUntouched(t *testing.T) {
	certPEM, skid := mustGenerateTestCA(t)

	pkir := buildIntermediatePKIR()
	pkir.Status.Phase = platformv1alpha1.PhaseIdle
	pkir.Status.CurrentSKID = skid

	r := intermediateFixture(t, pkir, certPEM)

	var before platformv1alpha1.PKIRotation
	if err := r.Get(context.Background(), types.NamespacedName{Name: pkir.Name}, &before); err != nil {
		t.Fatalf("reading before: %v", err)
	}

	if _, err := r.reconcileIdleIntermediate(context.Background(), pkir); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	var after platformv1alpha1.PKIRotation
	if err := r.Get(context.Background(), types.NamespacedName{Name: pkir.Name}, &after); err != nil {
		t.Fatalf("reading after: %v", err)
	}
	if after.ResourceVersion != before.ResourceVersion {
		t.Errorf("resourceVersion changed %s → %s; a settled CR must not be rewritten",
			before.ResourceVersion, after.ResourceVersion)
	}
}

// First run still sets both fields together — the outcome-2 path this repair
// must not have disturbed.
func TestReconcileIdleIntermediate_FirstRunSetsPhaseAndSKID(t *testing.T) {
	certPEM, skid := mustGenerateTestCA(t)

	pkir := buildIntermediatePKIR()
	pkir.Status.Phase = ""
	pkir.Status.CurrentSKID = "" // never seen before

	r := intermediateFixture(t, pkir, certPEM)

	if _, err := r.reconcileIdleIntermediate(context.Background(), pkir); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	var got platformv1alpha1.PKIRotation
	if err := r.Get(context.Background(), types.NamespacedName{Name: pkir.Name}, &got); err != nil {
		t.Fatalf("reading back: %v", err)
	}
	if got.Status.Phase != platformv1alpha1.PhaseIdle {
		t.Errorf("phase = %q, want Idle", got.Status.Phase)
	}
	if got.Status.CurrentSKID != skid {
		t.Errorf("currentSKID = %q, want %q", got.Status.CurrentSKID, skid)
	}
}
