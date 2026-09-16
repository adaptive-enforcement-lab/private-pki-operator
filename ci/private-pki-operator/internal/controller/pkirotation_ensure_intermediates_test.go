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

// testOldSKID is a sentinel SKID value used across syncChildSKIDs tests to represent
// a stale or pre-cascade SKID that needs updating or preserving.
const testOldSKID = "old-skid"

// buildRootPKIR constructs a minimal RootCA PKIRotation for testing ensureIntermediateCACRs.
func buildRootPKIR() *platformv1alpha1.PKIRotation {
	return &platformv1alpha1.PKIRotation{
		ObjectMeta: metav1.ObjectMeta{
			Name: "root-rotation",
			UID:  "root-uid-1234",
		},
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

// TestEnsureIntermediateCACRs_CreatesChildCR verifies that ensureIntermediateCACRs
// creates a child PKIRotation with role=IntermediateCA, correct spec.intermediateCA,
// and an owner reference pointing to the root PKIRotation.
func TestEnsureIntermediateCACRs_CreatesChildCR(t *testing.T) {
	// Root CA Certificate — the anchor for discovery.
	rootCACert := cmv1.Certificate{
		ObjectMeta: metav1.ObjectMeta{Name: "root-ca", Namespace: "cert-manager"},
		Spec: cmv1.CertificateSpec{
			SecretName: "root-ca-secret",
			IsCA:       true,
			// IssuerRef intentionally left empty — root is self-signed.
		},
	}

	// ClusterIssuer backed by the root CA Secret — this is the anchor issuers need.
	rootIssuer := newTestClusterIssuer("root-issuer", "root-ca-secret")

	// Intermediate CA Certificate signed by root-issuer.
	intCACert := newTestCA("int-ca", "cert-manager", "int-ca-secret", "root-issuer", "ClusterIssuer")

	rootPKIR := buildRootPKIR()

	c := fake.NewClientBuilder().
		WithScheme(makeCMScheme()).
		WithObjects(&rootCACert, &rootIssuer, &intCACert, rootPKIR).
		WithStatusSubresource(rootPKIR).
		Build()
	r := &PKIRotationReconciler{
		Client:   c,
		Scheme:   makeCMScheme(),
		Recorder: record.NewFakeRecorder(10),
	}

	err := r.ensureIntermediateCACRs(context.Background(), rootPKIR)
	if err != nil {
		t.Fatalf("ensureIntermediateCACRs: %v", err)
	}

	// Compute expected child name.
	expectedName := intermediateChildName("root-rotation", "cert-manager", "int-ca")

	var child platformv1alpha1.PKIRotation
	if err := c.Get(context.Background(), types.NamespacedName{Name: expectedName}, &child); err != nil {
		t.Fatalf("child PKIRotation %q not found: %v", expectedName, err)
	}

	// Role must be IntermediateCA.
	if child.Spec.Role != platformv1alpha1.RoleIntermediateCA {
		t.Errorf("expected role=IntermediateCA, got %s", child.Spec.Role)
	}

	// spec.intermediateCA must point to the discovered cert.
	if child.Spec.IntermediateCA == nil {
		t.Fatal("expected spec.intermediateCA to be set, got nil")
	}
	if child.Spec.IntermediateCA.CertificateName != "int-ca" {
		t.Errorf("expected intermediateCA.certificateName=int-ca, got %s", child.Spec.IntermediateCA.CertificateName)
	}
	if child.Spec.IntermediateCA.CertificateNamespace != "cert-manager" {
		t.Errorf(
			"expected intermediateCA.certificateNamespace=cert-manager, got %s",
			child.Spec.IntermediateCA.CertificateNamespace,
		)
	}

	// Owner reference must point to root PKIRotation.
	if len(child.OwnerReferences) != 1 {
		t.Fatalf("expected 1 owner reference, got %d", len(child.OwnerReferences))
	}
	ownerRef := child.OwnerReferences[0]
	if ownerRef.Name != rootPKIR.Name {
		t.Errorf("expected ownerRef.Name=%s, got %s", rootPKIR.Name, ownerRef.Name)
	}
	if ownerRef.Kind != pkirotationKind {
		t.Errorf("expected ownerRef.Kind=%s, got %s", pkirotationKind, ownerRef.Kind)
	}
	if ownerRef.APIVersion != pkirotationAPIVersion {
		t.Errorf("expected ownerRef.APIVersion=%s, got %s", pkirotationAPIVersion, ownerRef.APIVersion)
	}
	if ownerRef.Controller == nil || !*ownerRef.Controller {
		t.Error("expected ownerRef.Controller=true")
	}
}

// TestEnsureIntermediateCACRs_Idempotent verifies that calling ensureIntermediateCACRs
// twice produces no error and does not create a duplicate child CR.
func TestEnsureIntermediateCACRs_Idempotent(t *testing.T) {
	rootCACert := cmv1.Certificate{
		ObjectMeta: metav1.ObjectMeta{Name: "root-ca", Namespace: "cert-manager"},
		Spec:       cmv1.CertificateSpec{SecretName: "root-ca-secret", IsCA: true},
	}
	rootIssuer := newTestClusterIssuer("root-issuer", "root-ca-secret")
	intCACert := newTestCA("int-ca", "cert-manager", "int-ca-secret", "root-issuer", "ClusterIssuer")
	rootPKIR := buildRootPKIR()

	c := fake.NewClientBuilder().
		WithScheme(makeCMScheme()).
		WithObjects(&rootCACert, &rootIssuer, &intCACert, rootPKIR).
		WithStatusSubresource(rootPKIR).
		Build()
	r := &PKIRotationReconciler{
		Client:   c,
		Scheme:   makeCMScheme(),
		Recorder: record.NewFakeRecorder(10),
	}

	// First call.
	if err := r.ensureIntermediateCACRs(context.Background(), rootPKIR); err != nil {
		t.Fatalf("first call: %v", err)
	}

	// Second call — must be idempotent.
	if err := r.ensureIntermediateCACRs(context.Background(), rootPKIR); err != nil {
		t.Fatalf("second call (idempotency): %v", err)
	}

	// Exactly one child CR must exist.
	var list platformv1alpha1.PKIRotationList
	if err := c.List(context.Background(), &list); err != nil {
		t.Fatalf("listing PKIRotations: %v", err)
	}
	childCount := 0
	for _, item := range list.Items {
		if item.Name != rootPKIR.Name {
			childCount++
		}
	}
	if childCount != 1 {
		t.Errorf("expected exactly 1 child PKIRotation, found %d", childCount)
	}
}

// TestEnsureIntermediateCACRs_SetsBootstrapSKID verifies that when the intermediate
// CA's Secret already exists with a cert PEM, the newly created child PKIRotation's
// status.currentSKID is set to the cert's SKID (bootstrap to prevent false cascade).
func TestEnsureIntermediateCACRs_SetsBootstrapSKID(t *testing.T) {
	certPEM, expectedSKID := mustGenerateTestCA(t)

	rootCACert := cmv1.Certificate{
		ObjectMeta: metav1.ObjectMeta{Name: "root-ca", Namespace: "cert-manager"},
		Spec:       cmv1.CertificateSpec{SecretName: "root-ca-secret", IsCA: true},
	}
	rootIssuer := newTestClusterIssuer("root-issuer", "root-ca-secret")
	intCACert := newTestCA("int-ca", "cert-manager", "int-ca-secret", "root-issuer", "ClusterIssuer")
	intCASecret := corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{Name: "int-ca-secret", Namespace: "cert-manager"},
		Data:       map[string][]byte{"tls.crt": certPEM},
	}
	rootPKIR := buildRootPKIR()

	// The child PKIRotation must be in the StatusSubresource list so Status().Update works.
	childName := intermediateChildName("root-rotation", "cert-manager", "int-ca")
	childPKIR := &platformv1alpha1.PKIRotation{
		ObjectMeta: metav1.ObjectMeta{Name: childName},
	}

	c := fake.NewClientBuilder().
		WithScheme(makeCMScheme()).
		WithObjects(&rootCACert, &rootIssuer, &intCACert, &intCASecret, rootPKIR).
		WithStatusSubresource(rootPKIR, childPKIR).
		Build()
	r := &PKIRotationReconciler{
		Client:   c,
		Scheme:   makeCMScheme(),
		Recorder: record.NewFakeRecorder(10),
	}

	if err := r.ensureIntermediateCACRs(context.Background(), rootPKIR); err != nil {
		t.Fatalf("ensureIntermediateCACRs: %v", err)
	}

	// Fetch the child and check its status SKID.
	var child platformv1alpha1.PKIRotation
	if err := c.Get(context.Background(), types.NamespacedName{Name: childName}, &child); err != nil {
		t.Fatalf("child PKIRotation %q not found: %v", childName, err)
	}
	if child.Status.CurrentSKID != expectedSKID {
		t.Errorf("expected status.currentSKID=%s (bootstrap), got %q", expectedSKID, child.Status.CurrentSKID)
	}
}

// TestEnsureIntermediateCACRs_NoIssuers_ReturnsNil verifies that when the root CA
// Certificate exists but no Issuers/ClusterIssuers back it, ensureIntermediateCACRs
// returns nil and no child CRs are created.
func TestEnsureIntermediateCACRs_NoIssuers_ReturnsNil(t *testing.T) {
	// Root CA Certificate exists, but no issuers reference its secret.
	rootCACert := cmv1.Certificate{
		ObjectMeta: metav1.ObjectMeta{Name: "root-ca", Namespace: "cert-manager"},
		Spec:       cmv1.CertificateSpec{SecretName: "root-ca-secret", IsCA: true},
	}
	rootPKIR := buildRootPKIR()

	c := fake.NewClientBuilder().
		WithScheme(makeCMScheme()).
		WithObjects(&rootCACert, rootPKIR).
		WithStatusSubresource(rootPKIR).
		Build()
	r := &PKIRotationReconciler{
		Client:   c,
		Scheme:   makeCMScheme(),
		Recorder: record.NewFakeRecorder(10),
	}

	err := r.ensureIntermediateCACRs(context.Background(), rootPKIR)
	if err != nil {
		t.Fatalf("expected nil error when no issuers found, got: %v", err)
	}

	// No child CRs should be created.
	var list platformv1alpha1.PKIRotationList
	if err := c.List(context.Background(), &list); err != nil {
		t.Fatalf("listing PKIRotations: %v", err)
	}
	childCount := 0
	for _, item := range list.Items {
		if item.Name != rootPKIR.Name {
			childCount++
		}
	}
	if childCount != 0 {
		t.Errorf("expected 0 child PKIRotations when no issuers found, got %d", childCount)
	}
}

// ---------------------------------------------------------------------------
// syncChildSKIDs tests (Task 8)
// ---------------------------------------------------------------------------

// buildOwnedChildPKIR creates an IntermediateCA PKIRotation owned by rootPKIR,
// pointing to the intermediate CA cert at "int-ca" in "cert-manager".
// The ownerPKIRLabel is set so that syncChildSKIDs label-based list filtering works.
func buildOwnedChildPKIR(name string, rootPKIR *platformv1alpha1.PKIRotation) *platformv1alpha1.PKIRotation {
	return &platformv1alpha1.PKIRotation{
		ObjectMeta: metav1.ObjectMeta{
			Name: name,
			Labels: map[string]string{
				ownerPKIRLabel: rootPKIR.Name,
			},
			OwnerReferences: []metav1.OwnerReference{
				{
					APIVersion: pkirotationAPIVersion,
					Kind:       pkirotationKind,
					Name:       rootPKIR.Name,
					UID:        rootPKIR.UID,
					Controller: new(true),
				},
			},
		},
		Spec: platformv1alpha1.PKIRotationSpec{
			Role: platformv1alpha1.RoleIntermediateCA,
			IntermediateCA: &platformv1alpha1.IntermediateCARef{
				CertificateName:      "int-ca",
				CertificateNamespace: "cert-manager",
			},
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

// TestSyncChildSKIDs_UpdatesOutOfDateChild verifies that syncChildSKIDs updates
// a child CR whose status.currentSKID is out of date with the live Secret SKID,
// and clears status.previousSKID.
func TestSyncChildSKIDs_UpdatesOutOfDateChild(t *testing.T) {
	certPEM, newSKID := mustGenerateTestCA(t)

	rootPKIR := buildRootPKIR()

	intCACert := cmv1.Certificate{
		ObjectMeta: metav1.ObjectMeta{Name: "int-ca", Namespace: "cert-manager"},
		Spec:       cmv1.CertificateSpec{SecretName: "int-ca-secret", IsCA: true},
	}
	intCASecret := corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{Name: "int-ca-secret", Namespace: "cert-manager"},
		Data:       map[string][]byte{"tls.crt": certPEM},
	}

	childPKIR := buildOwnedChildPKIR("child-int-rotation", rootPKIR)
	childPKIR.Status.CurrentSKID = testOldSKID
	childPKIR.Status.PreviousSKID = "ancient-skid"

	c := fake.NewClientBuilder().
		WithScheme(makeCMScheme()).
		WithObjects(rootPKIR, &intCACert, &intCASecret, childPKIR).
		WithStatusSubresource(rootPKIR, childPKIR).
		Build()
	r := &PKIRotationReconciler{
		Client:   c,
		Scheme:   makeCMScheme(),
		Recorder: record.NewFakeRecorder(10),
	}

	if err := r.syncChildSKIDs(context.Background(), rootPKIR); err != nil {
		t.Fatalf("syncChildSKIDs: %v", err)
	}

	// Fetch the updated child from the fake store.
	var updated platformv1alpha1.PKIRotation
	if err := c.Get(context.Background(), types.NamespacedName{Name: childPKIR.Name}, &updated); err != nil {
		t.Fatalf("get child after sync: %v", err)
	}
	if updated.Status.CurrentSKID != newSKID {
		t.Errorf("expected status.currentSKID=%s, got %s", newSKID, updated.Status.CurrentSKID)
	}
	if updated.Status.PreviousSKID != "" {
		t.Errorf("expected status.previousSKID to be cleared, got %s", updated.Status.PreviousSKID)
	}
}

// TestSyncChildSKIDs_SkipsInSyncChild verifies that syncChildSKIDs does NOT call
// Status().Update when the child's currentSKID already matches the live Secret SKID.
func TestSyncChildSKIDs_SkipsInSyncChild(t *testing.T) {
	certPEM, skid := mustGenerateTestCA(t)

	rootPKIR := buildRootPKIR()

	intCACert := cmv1.Certificate{
		ObjectMeta: metav1.ObjectMeta{Name: "int-ca", Namespace: "cert-manager"},
		Spec:       cmv1.CertificateSpec{SecretName: "int-ca-secret", IsCA: true},
	}
	intCASecret := corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{Name: "int-ca-secret", Namespace: "cert-manager"},
		Data:       map[string][]byte{"tls.crt": certPEM},
	}

	childPKIR := buildOwnedChildPKIR("child-int-rotation", rootPKIR)
	childPKIR.Status.CurrentSKID = skid // already in sync

	c := fake.NewClientBuilder().
		WithScheme(makeCMScheme()).
		WithObjects(rootPKIR, &intCACert, &intCASecret, childPKIR).
		WithStatusSubresource(rootPKIR, childPKIR).
		Build()
	r := &PKIRotationReconciler{
		Client:   c,
		Scheme:   makeCMScheme(),
		Recorder: record.NewFakeRecorder(10),
	}

	if err := r.syncChildSKIDs(context.Background(), rootPKIR); err != nil {
		t.Fatalf("syncChildSKIDs: %v", err)
	}

	// Value must be preserved unchanged.
	var after platformv1alpha1.PKIRotation
	if err := c.Get(context.Background(), types.NamespacedName{Name: childPKIR.Name}, &after); err != nil {
		t.Fatalf("get child after sync: %v", err)
	}
	if after.Status.CurrentSKID != skid {
		t.Errorf("expected status.currentSKID unchanged (%s), got %s", skid, after.Status.CurrentSKID)
	}
}

// TestSyncChildSKIDs_OnlyUpdatesOwnedChildren verifies that syncChildSKIDs only
// updates IntermediateCA CRs that carry an owner reference pointing to rootPKIR.
// An IntermediateCA CR owned by a different root CR must not be modified.
func TestSyncChildSKIDs_OnlyUpdatesOwnedChildren(t *testing.T) {
	certPEM, newSKID := mustGenerateTestCA(t)

	rootPKIR := buildRootPKIR() // UID = "root-uid-1234"

	// A second root PKIRotation with a different UID.
	otherRoot := &platformv1alpha1.PKIRotation{
		ObjectMeta: metav1.ObjectMeta{
			Name: "other-root-rotation",
			UID:  "other-uid-9999",
		},
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

	// The child owned by rootPKIR — should be updated.
	ownedChild := buildOwnedChildPKIR("owned-child", rootPKIR)
	ownedChild.Status.CurrentSKID = testOldSKID
	// The child owned by otherRoot — must NOT be updated.
	// We reuse the same int-ca cert/secret for simplicity; only ownership differs.
	unownedChild := &platformv1alpha1.PKIRotation{
		ObjectMeta: metav1.ObjectMeta{
			Name: "unowned-child",
			OwnerReferences: []metav1.OwnerReference{
				{
					APIVersion: pkirotationAPIVersion,
					Kind:       pkirotationKind,
					Name:       otherRoot.Name,
					UID:        otherRoot.UID,
					Controller: new(true),
				},
			},
		},
		Spec: platformv1alpha1.PKIRotationSpec{
			Role: platformv1alpha1.RoleIntermediateCA,
			IntermediateCA: &platformv1alpha1.IntermediateCARef{
				CertificateName:      "int-ca",
				CertificateNamespace: "cert-manager",
			},
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
	unownedChild.Status.CurrentSKID = "unowned-old-skid"

	intCACert := cmv1.Certificate{
		ObjectMeta: metav1.ObjectMeta{Name: "int-ca", Namespace: "cert-manager"},
		Spec:       cmv1.CertificateSpec{SecretName: "int-ca-secret", IsCA: true},
	}
	intCASecret := corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{Name: "int-ca-secret", Namespace: "cert-manager"},
		Data:       map[string][]byte{"tls.crt": certPEM},
	}

	c := fake.NewClientBuilder().
		WithScheme(makeCMScheme()).
		WithObjects(rootPKIR, otherRoot, &intCACert, &intCASecret, ownedChild, unownedChild).
		WithStatusSubresource(rootPKIR, ownedChild, unownedChild).
		Build()
	r := &PKIRotationReconciler{
		Client:   c,
		Scheme:   makeCMScheme(),
		Recorder: record.NewFakeRecorder(10),
	}

	if err := r.syncChildSKIDs(context.Background(), rootPKIR); err != nil {
		t.Fatalf("syncChildSKIDs: %v", err)
	}

	// Owned child must be updated.
	var afterOwned platformv1alpha1.PKIRotation
	if err := c.Get(context.Background(), types.NamespacedName{Name: ownedChild.Name}, &afterOwned); err != nil {
		t.Fatalf("get ownedChild after sync: %v", err)
	}
	if afterOwned.Status.CurrentSKID != newSKID {
		t.Errorf("ownedChild: expected currentSKID=%s, got %s", newSKID, afterOwned.Status.CurrentSKID)
	}

	// Unowned child must NOT be updated.
	var afterUnowned platformv1alpha1.PKIRotation
	if err := c.Get(context.Background(), types.NamespacedName{Name: unownedChild.Name}, &afterUnowned); err != nil {
		t.Fatalf("get unownedChild after sync: %v", err)
	}
	if afterUnowned.Status.CurrentSKID != "unowned-old-skid" {
		t.Errorf(
			"unownedChild: expected currentSKID to remain 'unowned-old-skid', got %s",
			afterUnowned.Status.CurrentSKID,
		)
	}
}

// TestSyncChildSKIDs_DoesNotClearPreviousSKID_WhenCascadeActive verifies that
// syncChildSKIDs preserves status.previousSKID when the child PKIRotation is
// mid-cascade (e.g. in AwaitingReissuance phase).  Clearing PreviousSKID during
// an active cascade would corrupt the dual-trust window state machine; only the
// child's own reconcileCompleteIntermediate is allowed to clear it.
func TestSyncChildSKIDs_DoesNotClearPreviousSKID_WhenCascadeActive(t *testing.T) {
	certPEM, newSKID := mustGenerateTestCA(t)

	rootPKIR := buildRootPKIR()

	intCACert := cmv1.Certificate{
		ObjectMeta: metav1.ObjectMeta{Name: "int-ca", Namespace: "cert-manager"},
		Spec:       cmv1.CertificateSpec{SecretName: "int-ca-secret", IsCA: true},
	}
	intCASecret := corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{Name: "int-ca-secret", Namespace: "cert-manager"},
		Data:       map[string][]byte{"tls.crt": certPEM},
	}

	// Child is mid-cascade: AwaitingReissuance with a PreviousSKID that must
	// survive the sync. CurrentSKID is set to a stale value so that the diff
	// is detected and the update path is exercised (not the skip-branch).
	childPKIR := buildOwnedChildPKIR("child-mid-cascade", rootPKIR)
	childPKIR.Status.Phase = platformv1alpha1.PhaseAwaitingReissuance
	childPKIR.Status.CurrentSKID = "stale-skid" // differs from live Secret → update triggered
	childPKIR.Status.PreviousSKID = testOldSKID // must NOT be cleared

	c := fake.NewClientBuilder().
		WithScheme(makeCMScheme()).
		WithObjects(rootPKIR, &intCACert, &intCASecret, childPKIR).
		WithStatusSubresource(rootPKIR, childPKIR).
		Build()
	r := &PKIRotationReconciler{
		Client:   c,
		Scheme:   makeCMScheme(),
		Recorder: record.NewFakeRecorder(10),
	}

	if err := r.syncChildSKIDs(context.Background(), rootPKIR); err != nil {
		t.Fatalf("syncChildSKIDs: %v", err)
	}

	var updated platformv1alpha1.PKIRotation
	if err := c.Get(context.Background(), types.NamespacedName{Name: childPKIR.Name}, &updated); err != nil {
		t.Fatalf("get child after sync: %v", err)
	}

	// CurrentSKID must be refreshed to match the live Secret.
	if updated.Status.CurrentSKID != newSKID {
		t.Errorf("expected status.currentSKID=%s (live Secret), got %s", newSKID, updated.Status.CurrentSKID)
	}
	// PreviousSKID must be preserved — the child is mid-cascade and owns this field.
	if updated.Status.PreviousSKID != testOldSKID {
		t.Errorf(
			"expected status.previousSKID to be preserved as %q during active cascade, got %q", testOldSKID,
			updated.Status.PreviousSKID,
		)
	}
}
