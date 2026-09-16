package controller

import (
	"context"
	"testing"

	cmv1 "github.com/cert-manager/cert-manager/pkg/apis/certmanager/v1"
	cmmeta "github.com/cert-manager/cert-manager/pkg/apis/meta/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/tools/record"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"

	platformv1alpha1 "github.com/adaptive-enforcement-lab/private-pki-operator/ci/private-pki-operator/api/v1alpha1"
)

// PreservingOldRoot is the entry to the dual-trust window: the phase that decides
// whether a root CA renewal was a KEY rotation, which needs both roots trusted
// while the estate re-issues, or a same-key validity extension, which needs
// nothing. Getting that decision wrong is how trust breaks cluster-wide — either
// the old root is dropped while certificates still chain to it, or a rotation is
// mistaken for a no-op and never cascades.
//
// It had no tests at all.

// rootPKIR builds a role=RootCA PKIRotation pointing at root-ca/cert-manager.
func rootPKIR() *platformv1alpha1.PKIRotation {
	return &platformv1alpha1.PKIRotation{
		ObjectMeta: metav1.ObjectMeta{Name: "platform-root-ca"},
		Spec: platformv1alpha1.PKIRotationSpec{
			Role: platformv1alpha1.RoleRootCA,
			RootCA: platformv1alpha1.RootCARef{
				CertificateName:      "root-ca",
				CertificateNamespace: "cert-manager",
			},
			TrustBundle: platformv1alpha1.TrustBundleRef{
				Name: "platform-bundle",
				StagingConfigMap: platformv1alpha1.StagingConfigMapRef{
					Name:      "platform-staging",
					Namespace: "cert-manager",
				},
			},
		},
	}
}

// rootCAObjects returns the Certificate and backing Secret for the root CA,
// holding the given PEM.
func rootCAObjects(certPEM []byte) []client.Object {
	return []client.Object{
		&cmv1.Certificate{
			ObjectMeta: metav1.ObjectMeta{Name: "root-ca", Namespace: "cert-manager"},
			Spec:       cmv1.CertificateSpec{SecretName: "root-ca-secret", IsCA: true},
		},
		&corev1.Secret{
			ObjectMeta: metav1.ObjectMeta{Name: "root-ca-secret", Namespace: "cert-manager"},
			Data:       map[string][]byte{"tls.crt": certPEM},
		},
	}
}

// pendingCertificateRequest is an in-flight renewal of the root CA: a
// CertificateRequest annotated for root-ca that has not gone Ready.
func pendingCertificateRequest() *cmv1.CertificateRequest {
	return &cmv1.CertificateRequest{
		ObjectMeta: metav1.ObjectMeta{
			Name:        "root-ca-xyz",
			Namespace:   "cert-manager",
			Annotations: map[string]string{cmv1.CertificateNameKey: "root-ca"},
		},
		Status: cmv1.CertificateRequestStatus{
			Conditions: []cmv1.CertificateRequestCondition{
				{Type: cmv1.CertificateRequestConditionReady, Status: cmmeta.ConditionFalse},
			},
		},
	}
}

func preservingReconciler(t *testing.T, objs ...client.Object) (*PKIRotationReconciler, *platformv1alpha1.PKIRotation) {
	t.Helper()
	pkir := rootPKIR()
	pkir.Status.Phase = platformv1alpha1.PhasePreservingOldRoot
	all := append([]client.Object{pkir}, objs...)
	c := fake.NewClientBuilder().
		WithScheme(makeCMScheme()).
		WithObjects(all...).
		WithStatusSubresource(pkir).
		Build()
	return &PKIRotationReconciler{Client: c, Scheme: makeCMScheme(), Recorder: record.NewFakeRecorder(20)}, pkir
}

// The rotation case: the live SKID differs from the one recorded when the
// rotation started, so cert-manager issued a NEW KEY. Both roots must be trusted
// while the estate re-issues, which is what DualTrustActive opens.
func TestReconcilePreservingOldRoot_NewKeyOpensTheDualTrustWindow(t *testing.T) {
	newPEM, newSKID := mustGenerateTestCA(t)

	r, pkir := preservingReconciler(t, rootCAObjects(newPEM)...)
	pkir.Status.PreviousSKID = "AA:BB:CC:DD:EE:FF:00:11:22:33:44:55:66:77:88:99:AA:BB:CC:DD"

	if _, err := r.reconcilePreservingOldRoot(context.Background(), pkir); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if pkir.Status.Phase != platformv1alpha1.PhaseDualTrustActive {
		t.Errorf("phase = %q, want DualTrustActive — a new root key must open the dual-trust window", pkir.Status.Phase)
	}
	if pkir.Status.CurrentSKID != newSKID {
		t.Errorf("currentSKID = %q, want the live SKID %q", pkir.Status.CurrentSKID, newSKID)
	}
	if pkir.Status.PreviousSKID == "" {
		t.Error("previousSKID was cleared; the old root must stay identified until the cascade completes")
	}
}

// The same-key case: cert-manager extended the certificate's validity without
// changing the key (rotationPolicy: Never). Nothing chains to a different key,
// so opening a dual-trust window would be pure churn — and, worse, would trigger
// a full estate re-issuance for no reason.
func TestReconcilePreservingOldRoot_SameKeyRenewalAbortsToIdle(t *testing.T) {
	certPEM, skid := mustGenerateTestCA(t)

	r, pkir := preservingReconciler(t, rootCAObjects(certPEM)...)
	pkir.Status.PreviousSKID = skid // identical: renewal kept the key
	started := metav1.Now()
	pkir.Status.RotationStartedAt = &started

	if _, err := r.reconcilePreservingOldRoot(context.Background(), pkir); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if pkir.Status.Phase != platformv1alpha1.PhaseIdle {
		t.Errorf("phase = %q, want Idle — a same-key renewal is not a rotation", pkir.Status.Phase)
	}
	if pkir.Status.PreviousSKID != "" {
		t.Errorf("previousSKID = %q, want cleared — there is no old root to preserve", pkir.Status.PreviousSKID)
	}
	if pkir.Status.RotationStartedAt != nil {
		t.Error(
			"rotationStartedAt survived an aborted rotation; a later timeout would be " +
				"measured from a rotation that never happened",
		)
	}
}

// The in-flight case: the SKID has not moved YET, but a CertificateRequest for
// the root CA is still open. Concluding "same key" here would abandon a rotation
// mid-flight — the exact wrong answer, and indistinguishable from the previous
// case on SKID alone.
func TestReconcilePreservingOldRoot_WaitsWhileRenewalIsInFlight(t *testing.T) {
	certPEM, skid := mustGenerateTestCA(t)

	objs := append(rootCAObjects(certPEM), pendingCertificateRequest())
	r, pkir := preservingReconciler(t, objs...)
	pkir.Status.PreviousSKID = skid // unchanged so far

	result, err := r.reconcilePreservingOldRoot(context.Background(), pkir)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if result.RequeueAfter == 0 {
		t.Error("expected a requeue while the CertificateRequest is open; returning without one abandons the rotation")
	}
	if pkir.Status.Phase != platformv1alpha1.PhasePreservingOldRoot {
		t.Errorf(
			"phase = %q, want PreservingOldRoot — the rotation must not advance or abort while renewal is in flight",
			pkir.Status.Phase,
		)
	}
}

// A Ready CertificateRequest is a FINISHED renewal, not an in-flight one. With
// the SKID unchanged that means the key did not change, so this must abort like
// the same-key case rather than wait forever on a request that will never move.
func TestReconcilePreservingOldRoot_ReadyRequestCountsAsFinished(t *testing.T) {
	certPEM, skid := mustGenerateTestCA(t)

	done := pendingCertificateRequest()
	done.Status.Conditions[0].Status = cmmeta.ConditionTrue

	objs := append(rootCAObjects(certPEM), done)
	r, pkir := preservingReconciler(t, objs...)
	pkir.Status.PreviousSKID = skid

	if _, err := r.reconcilePreservingOldRoot(context.Background(), pkir); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if pkir.Status.Phase != platformv1alpha1.PhaseIdle {
		t.Errorf(
			"phase = %q, want Idle — a Ready request is a completed renewal, not a reason to keep waiting",
			pkir.Status.Phase,
		)
	}
}

// A CertificateRequest for a DIFFERENT certificate must not hold this rotation
// open. The namespace is shared, so an unrelated in-flight renewal is the normal
// state of a busy cluster.
func TestReconcilePreservingOldRoot_IgnoresUnrelatedCertificateRequests(t *testing.T) {
	certPEM, skid := mustGenerateTestCA(t)

	other := pendingCertificateRequest()
	other.Name = "some-other-cert-abc"
	other.Annotations[cmv1.CertificateNameKey] = "some-other-cert"

	objs := append(rootCAObjects(certPEM), other)
	r, pkir := preservingReconciler(t, objs...)
	pkir.Status.PreviousSKID = skid

	if _, err := r.reconcilePreservingOldRoot(context.Background(), pkir); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if pkir.Status.Phase != platformv1alpha1.PhaseIdle {
		t.Errorf("phase = %q, want Idle — another certificate's renewal must not gate this rotation", pkir.Status.Phase)
	}
}

// An unreadable root CA must surface as an error, never as a phase decision.
// Guessing here would either drop the old root or stall the rotation, and both
// are worse than failing the reconcile and retrying.
func TestReconcilePreservingOldRoot_MissingRootCAErrors(t *testing.T) {
	r, pkir := preservingReconciler(t) // no Certificate, no Secret
	pkir.Status.PreviousSKID = "AA:BB:CC"

	if _, err := r.reconcilePreservingOldRoot(context.Background(), pkir); err == nil {
		t.Fatal("expected an error when the root CA cannot be read, got nil")
	}
	if pkir.Status.Phase != platformv1alpha1.PhasePreservingOldRoot {
		t.Errorf("phase = %q, want it unchanged — a read failure must not move the state machine", pkir.Status.Phase)
	}
}

// The status write must actually land, not just mutate the in-memory object:
// a phase held only in memory is lost on the next reconcile, which is the
// failure class behind issue #259.
func TestReconcilePreservingOldRoot_PersistsThePhase(t *testing.T) {
	newPEM, _ := mustGenerateTestCA(t)

	r, pkir := preservingReconciler(t, rootCAObjects(newPEM)...)
	pkir.Status.PreviousSKID = "AA:BB:CC:DD:EE:FF:00:11:22:33:44:55:66:77:88:99:AA:BB:CC:DD"

	if _, err := r.reconcilePreservingOldRoot(context.Background(), pkir); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	var stored platformv1alpha1.PKIRotation
	if err := r.Get(context.Background(), types.NamespacedName{Name: pkir.Name}, &stored); err != nil {
		t.Fatalf("reading back: %v", err)
	}
	if stored.Status.Phase != platformv1alpha1.PhaseDualTrustActive {
		t.Errorf("persisted phase = %q, want DualTrustActive", stored.Status.Phase)
	}
}
