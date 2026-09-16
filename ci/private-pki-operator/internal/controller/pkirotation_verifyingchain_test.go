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
	"time"

	cmv1 "github.com/cert-manager/cert-manager/pkg/apis/certmanager/v1"
	cmmeta "github.com/cert-manager/cert-manager/pkg/apis/meta/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/tools/record"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"

	platformv1alpha1 "github.com/adaptive-enforcement-lab/private-pki-operator/ci/private-pki-operator/api/v1alpha1"
)

// TestReconcileVerifyingChain_LeafUsesPerNSNotBefore proves that a leaf cert in
// namespace "app-a" is checked against its direct tier-2 parent (app-a-ca), not
// the global max across all intermediates.
//
// Scenario:
//
//	T1 = tier1 (cluster intermediate) NotBefore
//	T2 = tier2-A (app-a-ca) NotBefore  — direct parent of leaf-a
//	T2half = leaf-a NotBefore           — between T2 and T3
//	T3 = tier2-B (app-b-ca) NotBefore  — LATER (simulates independent reissuance)
//
// With the old global-max check: leaf-a (T2half) < latestIntNotBefore (T3) → stuck forever.
// With the per-namespace check:  leaf-a (T2half) ≥ tier2-A.NotBefore (T2)  → PASS.
func TestReconcileVerifyingChain_LeafUsesPerNSNotBefore(t *testing.T) {
	now := time.Now().Truncate(time.Second)
	t0 := now.Add(-10 * time.Minute)   // root CA issued
	t1 := t0.Add(1 * time.Minute)      // tier-1 intermediate
	t2 := t1.Add(1 * time.Minute)      // tier-2 app-a (direct parent of leaf-a)
	t2half := t2.Add(30 * time.Second) // leaf-a — after app-a-ca but before app-b-ca
	t3 := t2.Add(1 * time.Minute)      // tier-2 app-b — the "late reissue"

	// Generate root CA key; tier-1 cert signed by root so its AKID = rootSKID.
	rootPEM, rootSKID, rootKey := mustGenerateTestCAWithKey(t, t0)
	tier1CertPEM := mustGenerateSignedCert(t, rootPEM, rootKey, t1) // AKID = rootSKID

	// ── Objects ──────────────────────────────────────────────────────────────

	// Root CA Certificate (anchor for discoverIntermediates).
	rootCACert := cmv1.Certificate{
		ObjectMeta: metav1.ObjectMeta{Name: "root-ca", Namespace: "cert-manager"},
		Spec: cmv1.CertificateSpec{
			SecretName: "root-ca-secret",
			IsCA:       true,
		},
	}
	// ClusterIssuer backed by root CA Secret — tier-1 certs use this issuer.
	rootIssuer := newTestClusterIssuer("root-issuer", "root-ca-secret")

	// Tier-1 cluster intermediate Certificate + Secret.
	tier1Cert := cmv1.Certificate{
		ObjectMeta: metav1.ObjectMeta{Name: "private-int-ca", Namespace: "cert-manager"},
		Spec: cmv1.CertificateSpec{ //nolint:gosec // G101: SecretName names a Secret object, not a credential
			SecretName: "private-int-ca-secret",
			IsCA:       true,
			IssuerRef:  cmmeta.IssuerReference{Name: "root-issuer", Kind: "ClusterIssuer"},
		},
		Status: cmv1.CertificateStatus{
			NotBefore: &metav1.Time{Time: t1},
			Conditions: []cmv1.CertificateCondition{
				{Type: cmv1.CertificateConditionReady, Status: cmmeta.ConditionTrue},
			},
		},
	}
	// Secret holds tier-1 cert PEM — AKID in tls.crt must equal rootSKID.
	tier1Secret := corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{Name: "private-int-ca-secret", Namespace: "cert-manager"},
		Data:       map[string][]byte{"tls.crt": tier1CertPEM},
	}
	// ClusterIssuer backed by tier-1 Secret — tier-2 certs use this issuer.
	tier1Issuer := newTestClusterIssuer("tier1-issuer", "private-int-ca-secret")

	// Tier-2 app-a: the direct parent of leaf-a. NotBefore = T2.
	tier2A := cmv1.Certificate{
		ObjectMeta: metav1.ObjectMeta{Name: "app-a-ca", Namespace: "app-a"},
		Spec: cmv1.CertificateSpec{ //nolint:gosec // G101: SecretName names a Secret object, not a credential
			SecretName: "app-a-ca-secret",
			IsCA:       true,
			IssuerRef:  cmmeta.IssuerReference{Name: "tier1-issuer", Kind: "ClusterIssuer"},
		},
		Status: cmv1.CertificateStatus{
			NotBefore: &metav1.Time{Time: t2},
			Conditions: []cmv1.CertificateCondition{
				{Type: cmv1.CertificateConditionReady, Status: cmmeta.ConditionTrue},
			},
		},
	}

	// Tier-2 app-b: an unrelated namespace intermediate reissued LATER (T3).
	// This is the "late reissue" that caused the global-max bug.
	tier2B := cmv1.Certificate{
		ObjectMeta: metav1.ObjectMeta{Name: "app-b-ca", Namespace: "app-b"},
		Spec: cmv1.CertificateSpec{ //nolint:gosec // G101: SecretName names a Secret object, not a credential
			SecretName: "app-b-ca-secret",
			IsCA:       true,
			IssuerRef:  cmmeta.IssuerReference{Name: "tier1-issuer", Kind: "ClusterIssuer"},
		},
		Status: cmv1.CertificateStatus{
			NotBefore: &metav1.Time{Time: t3},
			Conditions: []cmv1.CertificateCondition{
				{Type: cmv1.CertificateConditionReady, Status: cmmeta.ConditionTrue},
			},
		},
	}

	// Leaf cert in app-a namespace.
	// NotBefore = T2half: after app-a-ca (T2) but before app-b-ca (T3).
	// With per-NS check:  T2half ≥ T2 → PASS.
	// With old global-max: T2half < T3 → would have failed.
	leafA := cmv1.Certificate{
		ObjectMeta: metav1.ObjectMeta{Name: "leaf-a", Namespace: "app-a"},
		Spec: cmv1.CertificateSpec{ //nolint:gosec // G101: SecretName names a Secret object, not a credential
			SecretName: "leaf-a-tls",
			IsCA:       false,
			IssuerRef:  cmmeta.IssuerReference{Name: "app-a-issuer", Kind: "Issuer"},
		},
		Status: cmv1.CertificateStatus{
			NotBefore: &metav1.Time{Time: t2half},
			Conditions: []cmv1.CertificateCondition{
				{Type: cmv1.CertificateConditionReady, Status: cmmeta.ConditionTrue},
			},
		},
	}

	// Root PKIRotation in VerifyingChain phase.
	pkir := buildRootPKIR()
	pkir.Status.Phase = platformv1alpha1.PhaseVerifyingChain
	pkir.Status.CurrentSKID = rootSKID

	c := fake.NewClientBuilder().
		WithScheme(makeCMScheme()).
		WithObjects(&rootCACert, &rootIssuer, &tier1Cert, &tier1Secret, &tier1Issuer, &tier2A, &tier2B, &leafA, pkir).
		WithStatusSubresource(pkir).
		Build()
	r := &PKIRotationReconciler{
		Client:   c,
		Scheme:   makeCMScheme(),
		Recorder: record.NewFakeRecorder(10),
	}

	result, err := r.reconcileVerifyingChain(context.Background(), pkir)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.RequeueAfter != 0 {
		t.Errorf(
			"expected PASS (no requeue): leaf-a NotBefore is after its direct parent app-a-ca, got RequeueAfter=%v",
			result.RequeueAfter,
		)
	}
	if pkir.Status.Phase != platformv1alpha1.PhaseComplete {
		t.Errorf("expected phase Complete, got %s", pkir.Status.Phase)
	}

	var chainVerified *metav1.Condition
	for i := range pkir.Status.Conditions {
		if pkir.Status.Conditions[i].Type == platformv1alpha1.ConditionChainVerified {
			chainVerified = &pkir.Status.Conditions[i]
			break
		}
	}
	if chainVerified == nil || chainVerified.Status != metav1.ConditionTrue {
		status := condStatusNil
		if chainVerified != nil {
			status = string(chainVerified.Status)
		}
		t.Errorf("expected ChainVerified=True, got %s", status)
	}
}

// TestReconcileVerifyingChain_StaleLeafRetriggered proves that when a leaf cert's
// NotBefore is genuinely before its direct parent tier-2 intermediate, the operator
// re-triggers reissuance (sets Issuing=True) instead of waiting indefinitely.
func TestReconcileVerifyingChain_StaleLeafRetriggered(t *testing.T) {
	now := time.Now().Truncate(time.Second)
	t0 := now.Add(-10 * time.Minute)
	t1 := t0.Add(1 * time.Minute)
	t2 := t1.Add(1 * time.Minute) // tier-2 NotBefore
	// Leaf was issued BEFORE the tier-2 intermediate — must be re-triggered.
	leafOldNotBefore := t2.Add(-30 * time.Second)

	rootPEM, rootSKID, rootKey := mustGenerateTestCAWithKey(t, t0)
	tier1CertPEM := mustGenerateSignedCert(t, rootPEM, rootKey, t1)

	rootCACert := cmv1.Certificate{
		ObjectMeta: metav1.ObjectMeta{Name: "root-ca", Namespace: "cert-manager"},
		Spec:       cmv1.CertificateSpec{SecretName: "root-ca-secret", IsCA: true},
	}
	rootIssuer := newTestClusterIssuer("root-issuer", "root-ca-secret")
	tier1Cert := cmv1.Certificate{
		ObjectMeta: metav1.ObjectMeta{Name: "private-int-ca", Namespace: "cert-manager"},
		Spec: cmv1.CertificateSpec{ //nolint:gosec // G101: SecretName names a Secret object, not a credential
			SecretName: "private-int-ca-secret",
			IsCA:       true,
			IssuerRef:  cmmeta.IssuerReference{Name: "root-issuer", Kind: "ClusterIssuer"},
		},
		Status: cmv1.CertificateStatus{
			NotBefore: &metav1.Time{Time: t1},
			Conditions: []cmv1.CertificateCondition{
				{Type: cmv1.CertificateConditionReady, Status: cmmeta.ConditionTrue},
			},
		},
	}
	tier1Secret := corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{Name: "private-int-ca-secret", Namespace: "cert-manager"},
		Data:       map[string][]byte{"tls.crt": tier1CertPEM},
	}
	tier1Issuer := newTestClusterIssuer("tier1-issuer", "private-int-ca-secret")

	tier2 := cmv1.Certificate{
		ObjectMeta: metav1.ObjectMeta{Name: "app-ca", Namespace: "app"},
		Spec: cmv1.CertificateSpec{ //nolint:gosec // G101: SecretName names a Secret object, not a credential
			SecretName: "app-ca-secret",
			IsCA:       true,
			IssuerRef:  cmmeta.IssuerReference{Name: "tier1-issuer", Kind: "ClusterIssuer"},
		},
		Status: cmv1.CertificateStatus{
			NotBefore: &metav1.Time{Time: t2},
			Conditions: []cmv1.CertificateCondition{
				{Type: cmv1.CertificateConditionReady, Status: cmmeta.ConditionTrue},
			},
		},
	}
	// Leaf was issued before the tier-2 intermediate — stale, must be re-triggered.
	staleLeaf := cmv1.Certificate{
		ObjectMeta: metav1.ObjectMeta{Name: "leaf", Namespace: "app"},
		Spec: cmv1.CertificateSpec{
			SecretName: "leaf-tls",
			IsCA:       false,
			IssuerRef:  cmmeta.IssuerReference{Name: "app-issuer", Kind: "Issuer"},
		},
		Status: cmv1.CertificateStatus{
			NotBefore: &metav1.Time{Time: leafOldNotBefore},
			Conditions: []cmv1.CertificateCondition{
				{Type: cmv1.CertificateConditionReady, Status: cmmeta.ConditionTrue},
			},
		},
	}

	pkir := buildRootPKIR()
	pkir.Status.Phase = platformv1alpha1.PhaseVerifyingChain
	pkir.Status.CurrentSKID = rootSKID

	c := fake.NewClientBuilder().
		WithScheme(makeCMScheme()).
		WithObjects(&rootCACert, &rootIssuer, &tier1Cert, &tier1Secret, &tier1Issuer, &tier2, &staleLeaf, pkir).
		WithStatusSubresource(pkir, &staleLeaf).
		Build()
	r := &PKIRotationReconciler{
		Client:   c,
		Scheme:   makeCMScheme(),
		Recorder: record.NewFakeRecorder(10),
	}

	result, err := r.reconcileVerifyingChain(context.Background(), pkir)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	// Must requeue — leaf is genuinely stale.
	if result.RequeueAfter == 0 {
		t.Errorf("expected requeue for stale leaf, got no requeue")
	}
	if pkir.Status.Phase != platformv1alpha1.PhaseVerifyingChain {
		t.Errorf("expected phase to stay VerifyingChain, got %s", pkir.Status.Phase)
	}

	// Verify that the stale leaf was re-triggered: Issuing=True must be set.
	var updated cmv1.Certificate
	if err := c.Get(context.Background(), client.ObjectKey{Name: "leaf", Namespace: "app"}, &updated); err != nil {
		t.Fatalf("getting updated leaf cert: %v", err)
	}
	var issuingCond *cmv1.CertificateCondition
	for i := range updated.Status.Conditions {
		if updated.Status.Conditions[i].Type == cmv1.CertificateConditionIssuing {
			issuingCond = &updated.Status.Conditions[i]
			break
		}
	}
	if issuingCond == nil || issuingCond.Status != cmmeta.ConditionTrue {
		status := condStatusNil
		if issuingCond != nil {
			status = string(issuingCond.Status)
		}
		t.Errorf("expected stale leaf to be re-triggered (Issuing=True), got %s", status)
	}
}
