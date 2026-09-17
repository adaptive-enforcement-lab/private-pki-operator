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
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"strings"
	"testing"
	"time"

	"github.com/adaptive-enforcement-lab/private-pki-operator/ci/private-pki-operator/internal/pki"
	cmv1 "github.com/cert-manager/cert-manager/pkg/apis/certmanager/v1"
	cmmeta "github.com/cert-manager/cert-manager/pkg/apis/meta/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/tools/record"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"

	platformv1alpha1 "github.com/adaptive-enforcement-lab/private-pki-operator/ci/private-pki-operator/api/v1alpha1"
)

// condStatusNil is used in tests that print a condition status when none was found.
const condStatusNil = "<nil>"

// mustGenerateTestCA generates a self-signed CA cert PEM and returns (PEM bytes, SKID hex string).
func mustGenerateTestCA(t *testing.T) ([]byte, string) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	skidBytes := make([]byte, 20)
	if _, err := rand.Read(skidBytes); err != nil {
		t.Fatalf("generate SKID bytes: %v", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "test-ca"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		SubjectKeyId:          skidBytes,
		KeyUsage:              x509.KeyUsageCertSign,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("create cert: %v", err)
	}
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	skid, err := pki.SKIDFromPEM(certPEM)
	if err != nil {
		t.Fatalf("extract SKID: %v", err)
	}
	return certPEM, skid
}

// buildIntermediatePKIR constructs a PKIRotation with role=IntermediateCA for testing.
// Certificate is always "int-ca" in namespace "cert-manager".
func buildIntermediatePKIR() *platformv1alpha1.PKIRotation {
	return &platformv1alpha1.PKIRotation{
		ObjectMeta: metav1.ObjectMeta{
			Name: "int-rotation",
		},
		Spec: platformv1alpha1.PKIRotationSpec{
			Role: platformv1alpha1.RoleIntermediateCA,
			IntermediateCA: &platformv1alpha1.IntermediateCARef{
				CertificateName:      "int-ca",
				CertificateNamespace: "cert-manager",
			},
			// RootCA and TrustBundle are required fields but unused by intermediate logic.
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

// TestReconcileIdleIntermediate_NoChange verifies that when the SKID is unchanged,
// the phase stays Idle and only the periodic stale-child sweep is scheduled.
func TestReconcileIdleIntermediate_NoChange(t *testing.T) {
	certPEM, skid := mustGenerateTestCA(t)

	cert := cmv1.Certificate{
		ObjectMeta: metav1.ObjectMeta{Name: "int-ca", Namespace: "cert-manager"},
		Spec:       cmv1.CertificateSpec{SecretName: "int-ca-secret", IsCA: true},
	}
	secret := corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{Name: "int-ca-secret", Namespace: "cert-manager"},
		Data:       map[string][]byte{"tls.crt": certPEM},
	}

	pkir := buildIntermediatePKIR()
	pkir.Status.Phase = platformv1alpha1.PhaseIdle
	pkir.Status.CurrentSKID = skid // already recorded

	c := fake.NewClientBuilder().
		WithScheme(makeCMScheme()).
		WithObjects(&cert, &secret, pkir).
		WithStatusSubresource(pkir).
		Build()
	r := &PKIRotationReconciler{
		Client:   c,
		Scheme:   makeCMScheme(),
		Recorder: record.NewFakeRecorder(10),
	}

	result, err := r.reconcileIdleIntermediate(context.Background(), pkir)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.RequeueAfter != staleDownstreamSweepInterval {
		t.Errorf("expected RequeueAfter=%v (stale-child sweep), got %v", staleDownstreamSweepInterval, result.RequeueAfter)
	}
	if pkir.Status.Phase != platformv1alpha1.PhaseIdle {
		t.Errorf("expected phase Idle, got %s", pkir.Status.Phase)
	}
}

// TestReconcileIdleIntermediate_FirstRun verifies that on first run (empty currentSKID),
// the SKID is recorded in status, the phase stays Idle and the sweep is scheduled.
func TestReconcileIdleIntermediate_FirstRun(t *testing.T) {
	certPEM, skid := mustGenerateTestCA(t)

	cert := cmv1.Certificate{
		ObjectMeta: metav1.ObjectMeta{Name: "int-ca", Namespace: "cert-manager"},
		Spec:       cmv1.CertificateSpec{SecretName: "int-ca-secret", IsCA: true},
	}
	secret := corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{Name: "int-ca-secret", Namespace: "cert-manager"},
		Data:       map[string][]byte{"tls.crt": certPEM},
	}

	pkir := buildIntermediatePKIR()
	pkir.Status.Phase = platformv1alpha1.PhaseIdle
	pkir.Status.CurrentSKID = "" // first run — no SKID yet

	c := fake.NewClientBuilder().
		WithScheme(makeCMScheme()).
		WithObjects(&cert, &secret, pkir).
		WithStatusSubresource(pkir).
		Build()
	r := &PKIRotationReconciler{
		Client:   c,
		Scheme:   makeCMScheme(),
		Recorder: record.NewFakeRecorder(10),
	}

	result, err := r.reconcileIdleIntermediate(context.Background(), pkir)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.RequeueAfter != staleDownstreamSweepInterval {
		t.Errorf("expected RequeueAfter=%v on first run (stale-child sweep), got %v",
			staleDownstreamSweepInterval, result.RequeueAfter)
	}
	// The in-memory struct must have the SKID recorded.
	if pkir.Status.CurrentSKID != skid {
		t.Errorf("expected currentSKID=%s, got %s", skid, pkir.Status.CurrentSKID)
	}
	if pkir.Status.Phase != platformv1alpha1.PhaseIdle {
		t.Errorf("expected phase Idle, got %s", pkir.Status.Phase)
	}
}

// TestReconcileIdleIntermediate_SKIDChanged_OwnerIdle verifies that when the SKID
// changes and the owner PKIRotation is Idle, we transition to AwaitingReissuance.
func TestReconcileIdleIntermediate_SKIDChanged_OwnerIdle(t *testing.T) {
	certPEM, newSKID := mustGenerateTestCA(t)
	_, oldSKID := mustGenerateTestCA(t) // different cert = different SKID

	cert := cmv1.Certificate{
		ObjectMeta: metav1.ObjectMeta{Name: "int-ca", Namespace: "cert-manager"},
		Spec:       cmv1.CertificateSpec{SecretName: "int-ca-secret", IsCA: true},
	}
	secret := corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{Name: "int-ca-secret", Namespace: "cert-manager"},
		Data:       map[string][]byte{"tls.crt": certPEM},
	}

	ownerPKIR := &platformv1alpha1.PKIRotation{
		ObjectMeta: metav1.ObjectMeta{Name: "root-rotation"},
		Status: platformv1alpha1.PKIRotationStatus{
			Phase: platformv1alpha1.PhaseIdle,
		},
	}

	pkir := buildIntermediatePKIR()
	pkir.Status.Phase = platformv1alpha1.PhaseIdle
	pkir.Status.CurrentSKID = oldSKID
	pkir.OwnerReferences = []metav1.OwnerReference{
		{
			APIVersion: platformv1alpha1.GroupVersion.String(),
			Kind:       "PKIRotation",
			Name:       "root-rotation",
			UID:        "abc123",
		},
	}

	c := fake.NewClientBuilder().
		WithScheme(makeCMScheme()).
		WithObjects(&cert, &secret, pkir, ownerPKIR).
		WithStatusSubresource(pkir).
		Build()
	r := &PKIRotationReconciler{
		Client:   c,
		Scheme:   makeCMScheme(),
		Recorder: record.NewFakeRecorder(10),
	}

	result, err := r.reconcileIdleIntermediate(context.Background(), pkir)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.RequeueAfter != 0 {
		t.Errorf("expected no forced requeue (transition to AwaitingReissuance), got %v", result.RequeueAfter)
	}
	if pkir.Status.Phase != platformv1alpha1.PhaseAwaitingReissuance {
		t.Errorf("expected phase AwaitingReissuance, got %s", pkir.Status.Phase)
	}
	if pkir.Status.CurrentSKID != newSKID {
		t.Errorf("expected currentSKID=%s, got %s", newSKID, pkir.Status.CurrentSKID)
	}
}

// TestReconcileIdleIntermediate_SKIDChanged_OwnerNotIdle verifies that when the SKID
// changes but the owner PKIRotation is NOT Idle (e.g. DualTrustActive), the operator
// yields: stays Idle, requeues 30s, and updates currentSKID.
func TestReconcileIdleIntermediate_SKIDChanged_OwnerNotIdle(t *testing.T) {
	certPEM, newSKID := mustGenerateTestCA(t)
	_, oldSKID := mustGenerateTestCA(t) // different cert = different SKID

	cert := cmv1.Certificate{
		ObjectMeta: metav1.ObjectMeta{Name: "int-ca", Namespace: "cert-manager"},
		Spec:       cmv1.CertificateSpec{SecretName: "int-ca-secret", IsCA: true},
	}
	secret := corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{Name: "int-ca-secret", Namespace: "cert-manager"},
		Data:       map[string][]byte{"tls.crt": certPEM},
	}

	ownerPKIR := &platformv1alpha1.PKIRotation{
		ObjectMeta: metav1.ObjectMeta{Name: "root-rotation"},
		Status: platformv1alpha1.PKIRotationStatus{
			Phase: platformv1alpha1.PhaseDualTrustActive, // not Idle
		},
	}

	pkir := buildIntermediatePKIR()
	pkir.Status.Phase = platformv1alpha1.PhaseIdle
	pkir.Status.CurrentSKID = oldSKID
	pkir.OwnerReferences = []metav1.OwnerReference{
		{
			APIVersion: platformv1alpha1.GroupVersion.String(),
			Kind:       "PKIRotation",
			Name:       "root-rotation",
			UID:        "abc123",
		},
	}

	c := fake.NewClientBuilder().
		WithScheme(makeCMScheme()).
		WithObjects(&cert, &secret, pkir, ownerPKIR).
		WithStatusSubresource(pkir).
		Build()
	r := &PKIRotationReconciler{
		Client:   c,
		Scheme:   makeCMScheme(),
		Recorder: record.NewFakeRecorder(10),
	}

	result, err := r.reconcileIdleIntermediate(context.Background(), pkir)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Must requeue after 30s (yield behaviour).
	if result.RequeueAfter != 30*time.Second {
		t.Errorf("expected RequeueAfter=30s, got %v", result.RequeueAfter)
	}
	// Must stay Idle (not transition).
	if pkir.Status.Phase != platformv1alpha1.PhaseIdle {
		t.Errorf("expected phase Idle (yield), got %s", pkir.Status.Phase)
	}
	// currentSKID must be updated to the new value.
	if pkir.Status.CurrentSKID != newSKID {
		t.Errorf("expected currentSKID=%s after yield, got %s", newSKID, pkir.Status.CurrentSKID)
	}
}

// TestReconcileCompleteIntermediate verifies that the Complete phase clears
// previousSKID and rotationStartedAt, emits an event, and transitions to Idle.
func TestReconcileCompleteIntermediate(t *testing.T) {
	now := metav1.Now()
	pkir := buildIntermediatePKIR()
	pkir.Status.Phase = platformv1alpha1.PhaseComplete
	pkir.Status.CurrentSKID = "AA:BB:CC"
	pkir.Status.PreviousSKID = "11:22:33"
	pkir.Status.RotationStartedAt = &now

	c := fake.NewClientBuilder().
		WithScheme(makeCMScheme()).
		WithObjects(pkir).
		WithStatusSubresource(pkir).
		Build()
	recorder := record.NewFakeRecorder(10)
	r := &PKIRotationReconciler{
		Client:   c,
		Scheme:   makeCMScheme(),
		Recorder: recorder,
	}

	result, err := r.reconcileCompleteIntermediate(context.Background(), pkir)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.RequeueAfter != 0 {
		t.Errorf("expected no requeue after Complete, got %v", result.RequeueAfter)
	}

	// Phase must transition to Idle.
	if pkir.Status.Phase != platformv1alpha1.PhaseIdle {
		t.Errorf("expected phase Idle, got %s", pkir.Status.Phase)
	}
	// PreviousSKID must be cleared.
	if pkir.Status.PreviousSKID != "" {
		t.Errorf("expected empty previousSKID, got %s", pkir.Status.PreviousSKID)
	}
	// RotationStartedAt must be cleared.
	if pkir.Status.RotationStartedAt != nil {
		t.Errorf("expected nil rotationStartedAt, got %v", pkir.Status.RotationStartedAt)
	}
	// An event must have been emitted.
	select {
	case evt := <-recorder.Events:
		_ = evt // just confirm one was emitted
	default:
		t.Error("expected an event to be emitted, but none was")
	}
}

// mustGenerateTestCAWithKey generates a self-signed CA cert PEM with a given notBefore
// and returns (PEM bytes, SKID hex string, ECDSA private key).
// The caller owns the key and can use it to sign child certificates.
func mustGenerateTestCAWithKey(t *testing.T, notBefore time.Time) ([]byte, string, *ecdsa.PrivateKey) {
	t.Helper()
	skidBytes := make([]byte, 20)
	if _, err := rand.Read(skidBytes); err != nil {
		t.Fatalf("generate SKID bytes: %v", err)
	}
	return mustGenerateTestCAWithSKID(t, notBefore, skidBytes)
}

// mustGenerateTestCAWithSKID builds a CA with a caller-chosen Subject Key
// Identifier.
//
// Tests that turn on two CAs being DIFFERENT need that difference to be a fact,
// not a probability. The random variant above collides with probability 2^-160,
// which is never — but "never" was previously expressed as a t.Skip, and a skip
// is a test that silently does not run.
func mustGenerateTestCAWithSKID(
	t *testing.T, notBefore time.Time, skidBytes []byte,
) ([]byte, string, *ecdsa.PrivateKey) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate CA key: %v", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "test-intermediate-ca"},
		NotBefore:             notBefore,
		NotAfter:              notBefore.Add(24 * time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		SubjectKeyId:          skidBytes,
		KeyUsage:              x509.KeyUsageCertSign,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("create CA cert: %v", err)
	}
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	skid, err := pki.SKIDFromPEM(certPEM)
	if err != nil {
		t.Fatalf("extract SKID: %v", err)
	}
	return certPEM, skid, key
}

// mustGenerateSignedCert generates a leaf certificate signed by the given CA
// keypair. The leaf's AuthorityKeyId is set to the CA's SubjectKeyId so that
// AKIDFromPEM returns the CA's SKID. The notBefore parameter controls the
// leaf's NotBefore timestamp, allowing tests to create certs that predate
// (or postdate) the CA rotation.
func mustGenerateSignedCert(t *testing.T, caPEM []byte, caKey *ecdsa.PrivateKey, notBefore time.Time) []byte {
	t.Helper()

	// Parse the CA cert to get SubjectKeyId for AKID.
	caBlock, _ := pem.Decode(caPEM)
	if caBlock == nil {
		t.Fatalf("decode CA PEM: no PEM block")
	}
	caCert, err := x509.ParseCertificate(caBlock.Bytes)
	if err != nil {
		t.Fatalf("parse CA cert: %v", err)
	}

	leafKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate leaf key: %v", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber:   big.NewInt(42),
		Subject:        pkix.Name{CommonName: "test-leaf"},
		NotBefore:      notBefore,
		NotAfter:       notBefore.Add(24 * time.Hour),
		IsCA:           false,
		AuthorityKeyId: caCert.SubjectKeyId,
		KeyUsage:       x509.KeyUsageDigitalSignature,
		ExtKeyUsage:    []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, caCert, &leafKey.PublicKey, caKey)
	if err != nil {
		t.Fatalf("create leaf cert: %v", err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
}

// TestReconcileVerifyingChainIntermediate_AllMatch_Advances verifies that when
// all downstream certs are Ready and have NotBefore >= intermediate CA NotBefore,
// the function advances to Complete and sets ConditionChainVerified=True.
// It also verifies that ConditionIntermediateReissued is not set to False.
func TestReconcileVerifyingChainIntermediate_AllMatch_Advances(t *testing.T) {
	caNotBefore := time.Now().Add(-10 * time.Minute).Truncate(time.Second)
	leafNotBefore := caNotBefore // same second — equal is valid (regression guard)

	caPEM, skid, caKey := mustGenerateTestCAWithKey(t, caNotBefore)
	leafPEM := mustGenerateSignedCert(t, caPEM, caKey, leafNotBefore)

	// Intermediate CA Certificate + Secret.
	intCert := cmv1.Certificate{
		ObjectMeta: metav1.ObjectMeta{Name: "int-ca", Namespace: "cert-manager"},
		Spec: cmv1.CertificateSpec{
			SecretName: "int-ca-secret",
			IsCA:       true,
			IssuerRef:  cmmeta.IssuerReference{Name: "root-issuer", Kind: "ClusterIssuer"},
		},
		Status: cmv1.CertificateStatus{
			NotBefore: &metav1.Time{Time: caNotBefore},
			Conditions: []cmv1.CertificateCondition{
				{Type: cmv1.CertificateConditionReady, Status: cmmeta.ConditionTrue},
			},
		},
	}
	intSecret := corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{Name: "int-ca-secret", Namespace: "cert-manager"},
		Data:       map[string][]byte{"tls.crt": caPEM},
	}

	// ClusterIssuer backed by the intermediate CA Secret.
	intIssuer := newTestClusterIssuer("int-issuer", "int-ca-secret")

	// Leaf cert issued by the intermediate CA's ClusterIssuer.
	leafCert := cmv1.Certificate{
		ObjectMeta: metav1.ObjectMeta{Name: "leaf", Namespace: "cert-manager"},
		Spec: cmv1.CertificateSpec{
			SecretName: "leaf-secret",
			IsCA:       false,
			IssuerRef:  cmmeta.IssuerReference{Name: "int-issuer", Kind: "ClusterIssuer"},
		},
		Status: cmv1.CertificateStatus{
			NotBefore: &metav1.Time{Time: leafNotBefore},
			Conditions: []cmv1.CertificateCondition{
				{Type: cmv1.CertificateConditionReady, Status: cmmeta.ConditionTrue},
			},
		},
	}
	leafSecret := corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{Name: "leaf-secret", Namespace: "cert-manager"},
		Data:       map[string][]byte{"tls.crt": leafPEM},
	}

	pkir := buildIntermediatePKIR()
	pkir.Status.Phase = platformv1alpha1.PhaseVerifyingChain
	pkir.Status.CurrentSKID = skid

	c := fake.NewClientBuilder().
		WithScheme(makeCMScheme()).
		WithObjects(&intCert, &intSecret, &intIssuer, &leafCert, &leafSecret, pkir).
		WithStatusSubresource(pkir).
		Build()
	r := &PKIRotationReconciler{
		Client:   c,
		Scheme:   makeCMScheme(),
		Recorder: record.NewFakeRecorder(10),
	}

	result, err := r.reconcileVerifyingChainIntermediate(context.Background(), pkir)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.RequeueAfter != 0 {
		t.Errorf("expected no requeue on success path, got RequeueAfter=%v", result.RequeueAfter)
	}
	if pkir.Status.Phase != platformv1alpha1.PhaseComplete {
		t.Errorf("expected phase Complete, got %s", pkir.Status.Phase)
	}

	// ConditionIntermediateReissued must ALSO be True on the success path. It used
	// to be left at False/AwaitingCertManagerRenewal forever, contradicting the
	// ChainVerified=True set beside it (issue #260).
	var reissued *metav1.Condition
	for i := range pkir.Status.Conditions {
		if pkir.Status.Conditions[i].Type == platformv1alpha1.ConditionIntermediateReissued {
			reissued = &pkir.Status.Conditions[i]
			break
		}
	}
	if reissued == nil {
		t.Fatal("expected ConditionIntermediateReissued to be set, but it is absent")
	}
	if reissued.Status != metav1.ConditionTrue {
		t.Errorf(
			"IntermediateReissued = %s (reason %s), want True — a completed rotation must not report as awaiting renewal",
			reissued.Status, reissued.Reason,
		)
	}
	if reissued.Reason != platformv1alpha1.ReasonAllDownstreamReissued {
		t.Errorf(
			"IntermediateReissued reason = %q, want %q", reissued.Reason,
			platformv1alpha1.ReasonAllDownstreamReissued,
		)
	}

	// ConditionChainVerified must be True.
	var chainVerified *metav1.Condition
	for i := range pkir.Status.Conditions {
		if pkir.Status.Conditions[i].Type == platformv1alpha1.ConditionChainVerified {
			chainVerified = &pkir.Status.Conditions[i]
			break
		}
	}
	if chainVerified == nil {
		t.Fatal("expected ConditionChainVerified to be set, but it is absent")
	}
	if chainVerified.Status != metav1.ConditionTrue {
		t.Errorf(
			"expected ConditionChainVerified=True, got %s (message: %s)", chainVerified.Status, chainVerified.Message,
		)
	}

	// Issue 4: ConditionIntermediateReissued must NOT be False.
	for _, cond := range pkir.Status.Conditions {
		if cond.Type == platformv1alpha1.ConditionIntermediateReissued && cond.Status == metav1.ConditionFalse {
			t.Errorf(
				"ConditionIntermediateReissued must not be False on the happy path; got Status=%s Message=%s",
				cond.Status, cond.Message,
			)
		}
	}
}

// TestReconcileVerifyingChainIntermediate_NotBeforeTooOld_Requeues verifies that
// when a leaf cert's NotBefore is before the intermediate CA's NotBefore (it was
// issued before the intermediate CA rotation), the function requeues with 15s
// and keeps the phase at VerifyingChain.
func TestReconcileVerifyingChainIntermediate_NotBeforeTooOld_Requeues(t *testing.T) {
	caNotBefore := time.Now().Add(-10 * time.Minute).Truncate(time.Second)
	// Leaf was issued 1 hour BEFORE the CA rotation — NotBefore check must fail.
	leafNotBefore := caNotBefore.Add(-time.Hour)

	caPEM, skid, caKey := mustGenerateTestCAWithKey(t, caNotBefore)
	// Sign the leaf with the CA keypair so its AKID matches currentSKID.
	// This ensures the AKID check passes and only the NotBefore check fails.
	leafPEM := mustGenerateSignedCert(t, caPEM, caKey, leafNotBefore)

	// Intermediate CA Certificate + Secret.
	intCert := cmv1.Certificate{
		ObjectMeta: metav1.ObjectMeta{Name: "int-ca", Namespace: "cert-manager"},
		Spec: cmv1.CertificateSpec{
			SecretName: "int-ca-secret",
			IsCA:       true,
			IssuerRef:  cmmeta.IssuerReference{Name: "root-issuer", Kind: "ClusterIssuer"},
		},
		Status: cmv1.CertificateStatus{
			NotBefore: &metav1.Time{Time: caNotBefore},
			Conditions: []cmv1.CertificateCondition{
				{Type: cmv1.CertificateConditionReady, Status: cmmeta.ConditionTrue},
			},
		},
	}
	intSecret := corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{Name: "int-ca-secret", Namespace: "cert-manager"},
		Data:       map[string][]byte{"tls.crt": caPEM},
	}

	// ClusterIssuer backed by the intermediate CA Secret.
	intIssuer := newTestClusterIssuer("int-issuer", "int-ca-secret")

	// Leaf cert: Ready=True but NotBefore predates the intermediate CA rotation.
	leafCert := cmv1.Certificate{
		ObjectMeta: metav1.ObjectMeta{Name: "leaf", Namespace: "cert-manager"},
		Spec: cmv1.CertificateSpec{
			SecretName: "leaf-secret",
			IsCA:       false,
			IssuerRef:  cmmeta.IssuerReference{Name: "int-issuer", Kind: "ClusterIssuer"},
		},
		Status: cmv1.CertificateStatus{
			NotBefore: &metav1.Time{Time: leafNotBefore},
			Conditions: []cmv1.CertificateCondition{
				{Type: cmv1.CertificateConditionReady, Status: cmmeta.ConditionTrue},
			},
		},
	}
	leafSecret := corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{Name: "leaf-secret", Namespace: "cert-manager"},
		Data:       map[string][]byte{"tls.crt": leafPEM},
	}

	pkir := buildIntermediatePKIR()
	pkir.Status.Phase = platformv1alpha1.PhaseVerifyingChain
	pkir.Status.CurrentSKID = skid

	c := fake.NewClientBuilder().
		WithScheme(makeCMScheme()).
		WithObjects(&intCert, &intSecret, &intIssuer, &leafCert, &leafSecret, pkir).
		WithStatusSubresource(pkir).
		Build()
	r := &PKIRotationReconciler{
		Client:   c,
		Scheme:   makeCMScheme(),
		Recorder: record.NewFakeRecorder(10),
	}

	result, err := r.reconcileVerifyingChainIntermediate(context.Background(), pkir)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Must requeue after 15s — leaf NotBefore is too old.
	if result.RequeueAfter != 15*time.Second {
		t.Errorf("expected RequeueAfter=15s for stale NotBefore, got %v", result.RequeueAfter)
	}
	// Phase must stay at VerifyingChain.
	if pkir.Status.Phase != platformv1alpha1.PhaseVerifyingChain {
		t.Errorf("expected phase VerifyingChain, got %s", pkir.Status.Phase)
	}
}

// TestReconcileAwaitingReissuanceIntermediate_SKIDDrift_ResetsToIdle verifies that
// when the live intermediate CA SKID differs from pkir.Status.CurrentSKID
// (cert-manager rotated again mid-flight), the function emits a warning event,
// transitions back to Idle (so reconcileIdleIntermediate re-detects the new SKID
// and triggers a fresh cascade), and returns a zero-delay result.
func TestReconcileAwaitingReissuanceIntermediate_SKIDDrift_ResetsToIdle(t *testing.T) {
	// The two SKIDs are chosen, not drawn: this test turns entirely on them
	// differing, so the difference is stated rather than left to chance and
	// papered over with a skip when chance fails.
	oldSKID := bytes.Repeat([]byte{0x11}, 20)
	newSKIDBytes := bytes.Repeat([]byte{0x22}, 20)

	// currentSKID records the SKID that was present when reconcileIdleIntermediate ran.
	_, recordedSKID, _ := mustGenerateTestCAWithSKID(t, time.Now().Add(-time.Hour), oldSKID)

	// A second, newer CA cert is now in the Secret (cert-manager rotated again).
	newCAPEM, newSKID, _ := mustGenerateTestCAWithSKID(t, time.Now().Add(-time.Minute), newSKIDBytes)
	if newSKID == recordedSKID {
		t.Fatalf("fixture is broken: both CAs carry SKID %s", newSKID)
	}

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
		Data:       map[string][]byte{"tls.crt": newCAPEM}, // live Secret has the NEW cert
	}

	pkir := buildIntermediatePKIR()
	pkir.Status.Phase = platformv1alpha1.PhaseAwaitingReissuance
	pkir.Status.CurrentSKID = recordedSKID // stale — recorded before the second rotation

	recorder := record.NewFakeRecorder(10)
	c := fake.NewClientBuilder().
		WithScheme(makeCMScheme()).
		WithObjects(&intCert, &intSecret, pkir).
		WithStatusSubresource(pkir).
		Build()
	r := &PKIRotationReconciler{
		Client:   c,
		Scheme:   makeCMScheme(),
		Recorder: recorder,
	}

	result, err := r.reconcileAwaitingReissuanceIntermediate(context.Background(), pkir)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// transitionTo returns a zero result — no forced requeue delay.
	if result.RequeueAfter != 0 {
		t.Errorf("expected RequeueAfter=0 on SKID drift (transitionTo returns zero), got %v", result.RequeueAfter)
	}
	// Phase must have been reset to Idle so reconcileIdleIntermediate can re-detect the drift.
	if pkir.Status.Phase != platformv1alpha1.PhaseIdle {
		t.Errorf("expected phase Idle after SKID drift reset, got %s", pkir.Status.Phase)
	}
	// A SKIDDriftDetected warning event must have been emitted.
	select {
	case evt := <-recorder.Events:
		if evt == "" {
			t.Error("expected a SKIDDriftDetected event, got empty string")
		}
	default:
		t.Error("expected a warning event on SKID drift, but none was emitted")
	}
}

// TestReconcileVerifyingChainIntermediate_WrongAKID_Requeues verifies that when a
// downstream cert's backing Secret was signed by a *different* CA (AKID ≠ intermediate
// SKID), the function requeues with 15s and keeps phase at VerifyingChain.
// This covers the cryptographic chain check added to close the timing-only gap.
func TestReconcileVerifyingChainIntermediate_WrongAKID_Requeues(t *testing.T) {
	caNotBefore := time.Now().Add(-10 * time.Minute).Truncate(time.Second)
	leafNotBefore := caNotBefore.Add(time.Minute) // passes NotBefore check

	// Intermediate CA — the SKID recorded in pkir.Status.CurrentSKID.
	intCAPEM, intSKID, _ := mustGenerateTestCAWithKey(t, caNotBefore)

	// A different CA that signs the leaf — AKID will be otherSKID ≠ intSKID.
	otherCAPEM, _, otherKey := mustGenerateTestCAWithKey(t, caNotBefore)
	leafPEM := mustGenerateSignedCert(t, otherCAPEM, otherKey, leafNotBefore)

	intCert := cmv1.Certificate{
		ObjectMeta: metav1.ObjectMeta{Name: "int-ca", Namespace: "cert-manager"},
		Spec: cmv1.CertificateSpec{
			SecretName: "int-ca-secret", IsCA: true,
			IssuerRef: cmmeta.IssuerReference{Name: "root-issuer", Kind: "ClusterIssuer"},
		},
		Status: cmv1.CertificateStatus{
			NotBefore: &metav1.Time{Time: caNotBefore},
			Conditions: []cmv1.CertificateCondition{
				{Type: cmv1.CertificateConditionReady, Status: cmmeta.ConditionTrue},
			},
		},
	}
	intSecret := corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{Name: "int-ca-secret", Namespace: "cert-manager"},
		Data:       map[string][]byte{"tls.crt": intCAPEM},
	}
	intIssuer := newTestClusterIssuer("int-issuer", "int-ca-secret")

	leafCert := cmv1.Certificate{
		ObjectMeta: metav1.ObjectMeta{Name: "leaf", Namespace: "cert-manager"},
		Spec: cmv1.CertificateSpec{
			SecretName: "leaf-secret", IsCA: false,
			IssuerRef: cmmeta.IssuerReference{Name: "int-issuer", Kind: "ClusterIssuer"},
		},
		Status: cmv1.CertificateStatus{
			NotBefore: &metav1.Time{Time: leafNotBefore}, // passes NotBefore check
			Conditions: []cmv1.CertificateCondition{
				{Type: cmv1.CertificateConditionReady, Status: cmmeta.ConditionTrue},
			},
		},
	}
	leafSecret := corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{Name: "leaf-secret", Namespace: "cert-manager"},
		Data:       map[string][]byte{"tls.crt": leafPEM}, // signed by otherKey → wrong AKID
	}

	pkir := buildIntermediatePKIR()
	pkir.Status.Phase = platformv1alpha1.PhaseVerifyingChain
	pkir.Status.CurrentSKID = intSKID // intermediate SKID

	c := fake.NewClientBuilder().
		WithScheme(makeCMScheme()).
		WithObjects(&intCert, &intSecret, &intIssuer, &leafCert, &leafSecret, pkir).
		WithStatusSubresource(pkir).
		Build()
	r := &PKIRotationReconciler{
		Client:   c,
		Scheme:   makeCMScheme(),
		Recorder: record.NewFakeRecorder(10),
	}

	result, err := r.reconcileVerifyingChainIntermediate(context.Background(), pkir)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	// AKID mismatch → must requeue (cert not yet issued by the new intermediate).
	if result.RequeueAfter != 15*time.Second {
		t.Errorf("expected RequeueAfter=15s for AKID mismatch, got %v", result.RequeueAfter)
	}
	if pkir.Status.Phase != platformv1alpha1.PhaseVerifyingChain {
		t.Errorf("expected phase VerifyingChain, got %s", pkir.Status.Phase)
	}
}

// ---------------------------------------------------------------------------
// Role dispatch tests (Task 6)
// ---------------------------------------------------------------------------

// TestReconcile_IntermediateCA_RoutesToIdleIntermediate verifies that a PKIRotation
// with spec.role=IntermediateCA in Idle phase is routed to reconcileIdleIntermediate.
// When status.currentSKID already matches the live Secret SKID, the result must be
// no transition: no error, phase stays Idle, only the sweep is scheduled.
func TestReconcile_IntermediateCA_RoutesToIdleIntermediate(t *testing.T) {
	certPEM, skid := mustGenerateTestCA(t)

	cert := cmv1.Certificate{
		ObjectMeta: metav1.ObjectMeta{Name: "int-ca", Namespace: "cert-manager"},
		Spec:       cmv1.CertificateSpec{SecretName: "int-ca-secret", IsCA: true},
	}
	secret := corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{Name: "int-ca-secret", Namespace: "cert-manager"},
		Data:       map[string][]byte{"tls.crt": certPEM},
	}

	pkir := buildIntermediatePKIR()
	pkir.Status.Phase = platformv1alpha1.PhaseIdle
	pkir.Status.CurrentSKID = skid // already recorded — SKID unchanged

	c := fake.NewClientBuilder().
		WithScheme(makeCMScheme()).
		WithObjects(&cert, &secret, pkir).
		WithStatusSubresource(pkir).
		Build()
	r := &PKIRotationReconciler{
		Client:   c,
		Scheme:   makeCMScheme(),
		Recorder: record.NewFakeRecorder(10),
	}

	result, err := r.Reconcile(context.Background(), reconcileRequest(pkir.Name))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	// SKID unchanged → no transition; only the periodic stale-child sweep is scheduled.
	if result.RequeueAfter != staleDownstreamSweepInterval {
		t.Errorf("expected RequeueAfter=%v (stale-child sweep), got %v", staleDownstreamSweepInterval, result.RequeueAfter)
	}
	// Phase must still be Idle.
	if pkir.Status.Phase != platformv1alpha1.PhaseIdle {
		t.Errorf("expected phase Idle, got %s", pkir.Status.Phase)
	}
}

// TestReconcile_RootCA_NotRoutedToIntermediate verifies that a PKIRotation with
// spec.role=RootCA in Idle phase is NOT routed to the intermediate state machine.
// The root reconcileIdle path calls ensureStagingConfigMap, which fails when the
// staging ConfigMap is absent — confirming the root path was taken.
func TestReconcile_RootCA_NotRoutedToIntermediate(t *testing.T) {
	pkir := &platformv1alpha1.PKIRotation{
		ObjectMeta: metav1.ObjectMeta{Name: "root-rotation"},
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
		Status: platformv1alpha1.PKIRotationStatus{
			Phase: platformv1alpha1.PhaseIdle,
		},
	}

	// No root CA Secret or staging ConfigMap — root path will fail with a wrapped error.
	c := fake.NewClientBuilder().
		WithScheme(makeCMScheme()).
		WithObjects(pkir).
		WithStatusSubresource(pkir).
		Build()
	r := &PKIRotationReconciler{
		Client:   c,
		Scheme:   makeCMScheme(),
		Recorder: record.NewFakeRecorder(10),
	}

	_, err := r.Reconcile(context.Background(), reconcileRequest(pkir.Name))
	// The root reconcileIdle path returns an error when the staging ConfigMap is missing.
	// If the intermediate path were taken instead, reconcileIdleIntermediate would fail
	// with "spec.intermediateCA is nil" — a different sentinel. Either way we get an error
	// from the root path, which proves RootCA is not routed to the intermediate machine.
	if err == nil {
		t.Fatal("expected error from root path, got nil")
	}
	// Distinguish root path error from intermediate path error.
	// A routing regression would produce "spec.intermediateCA is nil" from the intermediate path.
	if strings.Contains(err.Error(), "spec.intermediateCA is nil") {
		t.Fatalf("routing regression: intermediate path taken for RootCA role; want root path error, got: %v", err)
	}
}

// TestReconcile_EmptyRole_RoutesToRootCA verifies that a PKIRotation with an empty
// spec.role field (omitempty default) is treated as RootCA and NOT routed to the
// intermediate state machine.
func TestReconcile_EmptyRole_RoutesToRootCA(t *testing.T) {
	pkir := &platformv1alpha1.PKIRotation{
		ObjectMeta: metav1.ObjectMeta{Name: "default-rotation"},
		Spec: platformv1alpha1.PKIRotationSpec{
			// Role intentionally omitted (empty string — default).
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
		Status: platformv1alpha1.PKIRotationStatus{
			Phase: platformv1alpha1.PhaseIdle,
		},
	}

	// No supporting resources — root path will fail with a staging ConfigMap error.
	c := fake.NewClientBuilder().
		WithScheme(makeCMScheme()).
		WithObjects(pkir).
		WithStatusSubresource(pkir).
		Build()
	r := &PKIRotationReconciler{
		Client:   c,
		Scheme:   makeCMScheme(),
		Recorder: record.NewFakeRecorder(10),
	}

	_, err := r.Reconcile(context.Background(), reconcileRequest(pkir.Name))
	// Same reasoning as TestReconcile_RootCA_NotRoutedToIntermediate:
	// the root path is taken (ensureStagingConfigMap fails) — NOT the intermediate path.
	if err == nil {
		t.Fatal("expected error from root path, got nil")
	}
	// Distinguish root path error from intermediate path error.
	// A routing regression would produce "spec.intermediateCA is nil" from the intermediate path.
	if strings.Contains(err.Error(), "spec.intermediateCA is nil") {
		t.Fatalf("routing regression: intermediate path taken for RootCA role; want root path error, got: %v", err)
	}
}

// reconcileRequest is a small helper that builds a ctrl.Request for a cluster-scoped resource.
func reconcileRequest(name string) ctrl.Request {
	return ctrl.Request{NamespacedName: types.NamespacedName{Name: name}}
}

// TestReconcileAwaitingReissuanceIntermediate_TriggersDownstreamAndAdvances is the
// happy-path test for the core cascade trigger: when the intermediate CA SKID has
// not drifted since reconcileIdleIntermediate ran, the function must discover all
// downstream certs, trigger their reissuance (set Issuing=True), and advance to
// PhaseVerifyingChain.
//
// This is the central test for the cascade functionality: without this path the
// entire downstream re-trigger mechanism is untested.
func TestReconcileAwaitingReissuanceIntermediate_TriggersDownstreamAndAdvances(t *testing.T) {
	now := time.Now().Truncate(time.Second)
	caPEM, skid, _ := mustGenerateTestCAWithKey(t, now.Add(-time.Minute))

	// Intermediate CA Certificate and its backing Secret (SKID matches pkir.CurrentSKID).
	intCert := cmv1.Certificate{
		ObjectMeta: metav1.ObjectMeta{Name: "int-ca", Namespace: "cert-manager"},
		Spec: cmv1.CertificateSpec{
			SecretName: "int-ca-secret",
			IsCA:       true,
			IssuerRef:  cmmeta.IssuerReference{Name: "root-issuer", Kind: "ClusterIssuer"},
		},
		Status: cmv1.CertificateStatus{
			NotBefore: &metav1.Time{Time: now.Add(-time.Minute)},
			Conditions: []cmv1.CertificateCondition{
				{Type: cmv1.CertificateConditionReady, Status: cmmeta.ConditionTrue},
			},
		},
	}
	intSecret := corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{Name: "int-ca-secret", Namespace: "cert-manager"},
		Data:       map[string][]byte{"tls.crt": caPEM},
	}

	// ClusterIssuer backed by the intermediate CA Secret — this is what
	// findIssuersForCACert discovers. Note: it is NOT the IssuerRef that signed
	// int-ca (root-issuer), so it will not be excluded as an ancestor.
	intIssuer := newTestClusterIssuer("int-issuer", "int-ca-secret")

	// Leaf certificate issued by the intermediate CA's ClusterIssuer — the
	// target of the cascade trigger.
	leafCert := cmv1.Certificate{
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
		WithObjects(&intCert, &intSecret, &intIssuer, &leafCert, pkir).
		WithStatusSubresource(pkir, &leafCert).
		Build()
	r := &PKIRotationReconciler{
		Client:   c,
		Scheme:   makeCMScheme(),
		Recorder: record.NewFakeRecorder(10),
	}

	result, err := r.reconcileAwaitingReissuanceIntermediate(context.Background(), pkir)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	// transitionTo returns zero result.
	if result.RequeueAfter != 0 {
		t.Errorf("expected RequeueAfter=0 on happy path, got %v", result.RequeueAfter)
	}
	// Phase must advance to VerifyingChain.
	if pkir.Status.Phase != platformv1alpha1.PhaseVerifyingChain {
		t.Errorf("expected phase VerifyingChain, got %s", pkir.Status.Phase)
	}
	// ConditionIntermediateReissued must be False (awaiting cert-manager renewal).
	var intReissued *metav1.Condition
	for i := range pkir.Status.Conditions {
		if pkir.Status.Conditions[i].Type == platformv1alpha1.ConditionIntermediateReissued {
			intReissued = &pkir.Status.Conditions[i]
			break
		}
	}
	if intReissued == nil || intReissued.Status != metav1.ConditionFalse {
		status := condStatusNil
		if intReissued != nil {
			status = string(intReissued.Status)
		}
		t.Errorf("expected ConditionIntermediateReissued=False (awaiting renewal), got %s", status)
	}

	// The leaf cert must have been triggered: Issuing=True must be set.
	var updatedLeaf cmv1.Certificate
	leafKey := types.NamespacedName{Name: "leaf", Namespace: "cert-manager"}
	if err := c.Get(context.Background(), leafKey, &updatedLeaf); err != nil {
		t.Fatalf("getting updated leaf cert: %v", err)
	}
	var issuingCond *cmv1.CertificateCondition
	for i := range updatedLeaf.Status.Conditions {
		if updatedLeaf.Status.Conditions[i].Type == cmv1.CertificateConditionIssuing {
			issuingCond = &updatedLeaf.Status.Conditions[i]
			break
		}
	}
	if issuingCond == nil || issuingCond.Status != cmmeta.ConditionTrue {
		status := condStatusNil
		if issuingCond != nil {
			status = string(issuingCond.Status)
		}
		t.Errorf("expected leaf cert to have Issuing=True after cascade trigger, got %s", status)
	}
}

// TestIntermediateCascade_FullPhaseProgression drives the entire intermediate CA
// cascade state machine end-to-end through three handler calls:
//
//	AwaitingReissuance → VerifyingChain → Complete → Idle
//
// This is the integration-level proof that all three cascade phases compose
// correctly: triggering downstream certs, verifying the chain, and cleaning up.
func TestIntermediateCascade_FullPhaseProgression(t *testing.T) {
	caNotBefore := time.Now().Add(-5 * time.Minute).Truncate(time.Second)
	// Leaf is issued AFTER the intermediate CA — this is the post-cascade state.
	leafNotBefore := caNotBefore.Add(time.Minute)

	caPEM, skid, caKey := mustGenerateTestCAWithKey(t, caNotBefore)
	// Leaf cert signed by the intermediate CA: AKID = intermediate SKID.
	leafPEM := mustGenerateSignedCert(t, caPEM, caKey, leafNotBefore)

	intCert := cmv1.Certificate{
		ObjectMeta: metav1.ObjectMeta{Name: "int-ca", Namespace: "cert-manager"},
		Spec: cmv1.CertificateSpec{
			SecretName: "int-ca-secret",
			IsCA:       true,
			IssuerRef:  cmmeta.IssuerReference{Name: "root-issuer", Kind: "ClusterIssuer"},
		},
		Status: cmv1.CertificateStatus{
			NotBefore: &metav1.Time{Time: caNotBefore},
			Conditions: []cmv1.CertificateCondition{
				{Type: cmv1.CertificateConditionReady, Status: cmmeta.ConditionTrue},
			},
		},
	}
	intSecret := corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{Name: "int-ca-secret", Namespace: "cert-manager"},
		Data:       map[string][]byte{"tls.crt": caPEM},
	}
	intIssuer := newTestClusterIssuer("int-issuer", "int-ca-secret")

	leafCert := cmv1.Certificate{
		ObjectMeta: metav1.ObjectMeta{Name: "leaf", Namespace: "cert-manager"},
		Spec: cmv1.CertificateSpec{
			SecretName: "leaf-secret",
			IsCA:       false,
			IssuerRef:  cmmeta.IssuerReference{Name: "int-issuer", Kind: "ClusterIssuer"},
		},
		Status: cmv1.CertificateStatus{
			NotBefore: &metav1.Time{Time: leafNotBefore},
			Conditions: []cmv1.CertificateCondition{
				{Type: cmv1.CertificateConditionReady, Status: cmmeta.ConditionTrue},
			},
		},
	}
	// Leaf Secret with properly signed cert (AKID = intermediate SKID) — required
	// for the AKID chain check in reconcileVerifyingChainIntermediate.
	leafSecret := corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{Name: "leaf-secret", Namespace: "cert-manager"},
		Data:       map[string][]byte{"tls.crt": leafPEM},
	}

	pkir := buildIntermediatePKIR()
	pkir.Status.Phase = platformv1alpha1.PhaseAwaitingReissuance
	pkir.Status.CurrentSKID = skid
	pkir.Status.PreviousSKID = "AA:BB:CC:DD" // set to prove Complete clears it

	c := fake.NewClientBuilder().
		WithScheme(makeCMScheme()).
		WithObjects(&intCert, &intSecret, &intIssuer, &leafCert, &leafSecret, pkir).
		WithStatusSubresource(pkir, &leafCert).
		Build()
	r := &PKIRotationReconciler{
		Client:   c,
		Scheme:   makeCMScheme(),
		Recorder: record.NewFakeRecorder(20),
	}

	// ── Phase 1: AwaitingReissuance → VerifyingChain ─────────────────────────
	// The cascade trigger: discovers leaf, sets Issuing=True, advances phase.
	result, err := r.reconcileAwaitingReissuanceIntermediate(context.Background(), pkir)
	if err != nil {
		t.Fatalf("AwaitingReissuance: unexpected error: %v", err)
	}
	if result.RequeueAfter != 0 {
		t.Errorf("AwaitingReissuance: expected no requeue, got %v", result.RequeueAfter)
	}
	if pkir.Status.Phase != platformv1alpha1.PhaseVerifyingChain {
		t.Fatalf("AwaitingReissuance: expected phase VerifyingChain, got %s", pkir.Status.Phase)
	}

	// ── Phase 2: VerifyingChain → Complete ───────────────────────────────────
	// The leaf cert's NotBefore and AKID already match — chain is valid.
	result, err = r.reconcileVerifyingChainIntermediate(context.Background(), pkir)
	if err != nil {
		t.Fatalf("VerifyingChain: unexpected error: %v", err)
	}
	if result.RequeueAfter != 0 {
		t.Errorf("VerifyingChain: expected no requeue on verified chain, got %v", result.RequeueAfter)
	}
	if pkir.Status.Phase != platformv1alpha1.PhaseComplete {
		t.Fatalf("VerifyingChain: expected phase Complete, got %s", pkir.Status.Phase)
	}
	// ChainVerified must be True.
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
		t.Errorf("VerifyingChain: expected ChainVerified=True, got %s", status)
	}

	// ── Phase 3: Complete → Idle ──────────────────────────────────────────────
	// Cleans up PreviousSKID, emits event, returns to Idle.
	result, err = r.reconcileCompleteIntermediate(context.Background(), pkir)
	if err != nil {
		t.Fatalf("Complete: unexpected error: %v", err)
	}
	if result.RequeueAfter != 0 {
		t.Errorf("Complete: expected no requeue, got %v", result.RequeueAfter)
	}
	if pkir.Status.Phase != platformv1alpha1.PhaseIdle {
		t.Errorf("Complete: expected phase Idle, got %s", pkir.Status.Phase)
	}
	if pkir.Status.PreviousSKID != "" {
		t.Errorf("Complete: expected PreviousSKID cleared, got %s", pkir.Status.PreviousSKID)
	}
}
