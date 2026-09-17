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
	"crypto/ecdsa"
	"testing"
	"time"

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

// staleSweepFixture is an intermediate CA "int-ca" (cert-manager namespace)
// backing ClusterIssuer "int-issuer", plus a key that USED to be the
// intermediate's — the one a stale child is signed by.
type staleSweepFixture struct {
	intCert   cmv1.Certificate
	intSecret corev1.Secret
	intIssuer cmv1.ClusterIssuer
	intSKID   string
	oldPEM    []byte
	newPEM    []byte
	oldKey    *ecdsa.PrivateKey
	newKey    *ecdsa.PrivateKey
}

func newStaleSweepFixture(t *testing.T) staleSweepFixture {
	t.Helper()
	now := time.Now().Truncate(time.Second)
	oldPEM, _, oldKey := mustGenerateTestCAWithSKID(t, now.Add(-60*24*time.Hour), []byte{0x0a, 0x01})
	newPEM, newSKID, newKey := mustGenerateTestCAWithSKID(t, now.Add(-30*24*time.Hour), []byte{0x0b, 0x02})
	return staleSweepFixture{
		intCert: cmv1.Certificate{
			ObjectMeta: metav1.ObjectMeta{Name: "int-ca", Namespace: "cert-manager"},
			Spec: cmv1.CertificateSpec{
				SecretName: "int-ca-secret", IsCA: true,
				IssuerRef: cmmeta.IssuerReference{Name: "root-issuer", Kind: issuerKindClusterIssuer},
			},
			Status: cmv1.CertificateStatus{Conditions: readyConditions()},
		},
		intSecret: corev1.Secret{
			ObjectMeta: metav1.ObjectMeta{Name: "int-ca-secret", Namespace: "cert-manager"},
			Data:       map[string][]byte{"tls.crt": newPEM},
		},
		intIssuer: newTestClusterIssuer("int-issuer", "int-ca-secret"),
		intSKID:   newSKID,
		oldPEM:    oldPEM,
		newPEM:    newPEM,
		oldKey:    oldKey,
		newKey:    newKey,
	}
}

func readyConditions() []cmv1.CertificateCondition {
	return []cmv1.CertificateCondition{{Type: cmv1.CertificateConditionReady, Status: cmmeta.ConditionTrue}}
}

// childCert returns a Certificate issued by issuerKind/issuerName plus its
// Secret holding tlsCrt.
func childCert(name, ns, issuerName, issuerKind string, tlsCrt []byte) (cmv1.Certificate, corev1.Secret) {
	return cmv1.Certificate{
		ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: ns},
		Spec: cmv1.CertificateSpec{
			SecretName: name + "-tls",
			IssuerRef:  cmmeta.IssuerReference{Name: issuerName, Kind: issuerKind},
		},
		Status: cmv1.CertificateStatus{Conditions: readyConditions()},
	}, corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{Name: name + "-tls", Namespace: ns},
		Data:       map[string][]byte{"tls.crt": tlsCrt},
	}
}

func issuingCondition(t *testing.T, c client.Client, name, ns string) *cmv1.CertificateCondition {
	t.Helper()
	var cert cmv1.Certificate
	if err := c.Get(context.Background(), types.NamespacedName{Name: name, Namespace: ns}, &cert); err != nil {
		t.Fatalf("getting certificate %s/%s: %v", ns, name, err)
	}
	for i := range cert.Status.Conditions {
		if cert.Status.Conditions[i].Type == cmv1.CertificateConditionIssuing {
			return &cert.Status.Conditions[i]
		}
	}
	return nil
}

func sweepReconciler(objs []client.Object, statusObjs []client.Object) (*PKIRotationReconciler, client.Client) {
	c := fake.NewClientBuilder().
		WithScheme(makeCMScheme()).
		WithObjects(objs...).
		WithStatusSubresource(statusObjs...).
		Build()
	return &PKIRotationReconciler{Client: c, Scheme: makeCMScheme(), Recorder: record.NewFakeRecorder(20)}, c
}

// A child signed by the intermediate's PREVIOUS key while the PKIRotation sits
// Idle with an unchanged SKID is exactly the state that took Hubble down: the
// intermediate rotated before anything watched it, so no cascade ever ran.
func TestReconcileIdleIntermediate_StaleChild_SKIDUnchanged_TriggersReissuance(t *testing.T) {
	f := newStaleSweepFixture(t)
	stalePEM := mustGenerateSignedCert(t, f.oldPEM, f.oldKey, time.Now().Add(-40*24*time.Hour))
	leaf, leafSecret := childCert("hubble-server-certs", "kube-system", "int-issuer", issuerKindClusterIssuer, stalePEM)

	pkir := buildIntermediatePKIR()
	pkir.Status.Phase = platformv1alpha1.PhaseIdle
	pkir.Status.CurrentSKID = f.intSKID

	r, c := sweepReconciler(
		[]client.Object{&f.intCert, &f.intSecret, &f.intIssuer, &leaf, &leafSecret, pkir},
		[]client.Object{pkir, &leaf},
	)

	result, err := r.reconcileIdleIntermediate(context.Background(), pkir)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	cond := issuingCondition(t, c, "hubble-server-certs", "kube-system")
	if cond == nil || cond.Status != cmmeta.ConditionTrue {
		t.Fatalf("expected stale child to be re-issued (Issuing=True), got %v", cond)
	}
	if pkir.Status.Phase != platformv1alpha1.PhaseIdle {
		t.Errorf("sweep must not leave Idle, got %s", pkir.Status.Phase)
	}
	if result.RequeueAfter != staleDownstreamSweepInterval {
		t.Errorf("expected RequeueAfter=%v so the sweep repeats, got %v", staleDownstreamSweepInterval, result.RequeueAfter)
	}
}

// First run records the baseline SKID. It must ALSO check the children that
// already exist: the operator being installed after an intermediate rotation is
// how the stale Hubble certificates were grandfathered in.
func TestReconcileIdleIntermediate_StaleChild_FirstRun_TriggersReissuance(t *testing.T) {
	f := newStaleSweepFixture(t)
	stalePEM := mustGenerateSignedCert(t, f.oldPEM, f.oldKey, time.Now().Add(-40*24*time.Hour))
	leaf, leafSecret := childCert("leaf", "kube-system", "int-issuer", issuerKindClusterIssuer, stalePEM)

	pkir := buildIntermediatePKIR()
	pkir.Status.Phase = platformv1alpha1.PhaseIdle

	r, c := sweepReconciler(
		[]client.Object{&f.intCert, &f.intSecret, &f.intIssuer, &leaf, &leafSecret, pkir},
		[]client.Object{pkir, &leaf},
	)

	result, err := r.reconcileIdleIntermediate(context.Background(), pkir)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if pkir.Status.CurrentSKID != f.intSKID {
		t.Errorf("expected baseline SKID %s recorded, got %s", f.intSKID, pkir.Status.CurrentSKID)
	}
	cond := issuingCondition(t, c, "leaf", "kube-system")
	if cond == nil || cond.Status != cmmeta.ConditionTrue {
		t.Fatalf("expected stale child to be re-issued on first run, got %v", cond)
	}
	if result.RequeueAfter != staleDownstreamSweepInterval {
		t.Errorf("expected RequeueAfter=%v, got %v", staleDownstreamSweepInterval, result.RequeueAfter)
	}
}

// A child signed by the current key is left alone.
func TestReconcileIdleIntermediate_CurrentChild_NotTriggered(t *testing.T) {
	f := newStaleSweepFixture(t)
	currentPEM := mustGenerateSignedCert(t, f.newPEM, f.newKey, time.Now().Add(-time.Hour))
	leaf, leafSecret := childCert("leaf", "kube-system", "int-issuer", issuerKindClusterIssuer, currentPEM)

	pkir := buildIntermediatePKIR()
	pkir.Status.Phase = platformv1alpha1.PhaseIdle
	pkir.Status.CurrentSKID = f.intSKID

	r, c := sweepReconciler(
		[]client.Object{&f.intCert, &f.intSecret, &f.intIssuer, &leaf, &leafSecret, pkir},
		[]client.Object{pkir, &leaf},
	)

	if _, err := r.reconcileIdleIntermediate(context.Background(), pkir); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if cond := issuingCondition(t, c, "leaf", "kube-system"); cond != nil {
		t.Errorf("current child must not be re-issued, got Issuing=%s", cond.Status)
	}
}

// A child cert-manager is already re-issuing, or that is not Ready, is not
// re-triggered: the first is in flight, the second is failing for its own
// reason and re-triggering it every sweep would only add noise.
func TestReconcileIdleIntermediate_StaleChild_InFlightOrNotReady_NotTriggered(t *testing.T) {
	f := newStaleSweepFixture(t)
	stalePEM := mustGenerateSignedCert(t, f.oldPEM, f.oldKey, time.Now().Add(-40*24*time.Hour))

	inFlight, inFlightSecret := childCert("in-flight", "kube-system", "int-issuer", issuerKindClusterIssuer, stalePEM)
	inFlight.Status.Conditions = append(inFlight.Status.Conditions, cmv1.CertificateCondition{
		Type: cmv1.CertificateConditionIssuing, Status: cmmeta.ConditionTrue, Reason: "Renewing",
	})
	notReady, notReadySecret := childCert("not-ready", "kube-system", "int-issuer", issuerKindClusterIssuer, stalePEM)
	notReady.Status.Conditions = []cmv1.CertificateCondition{
		{Type: cmv1.CertificateConditionReady, Status: cmmeta.ConditionFalse},
	}

	pkir := buildIntermediatePKIR()
	pkir.Status.Phase = platformv1alpha1.PhaseIdle
	pkir.Status.CurrentSKID = f.intSKID

	r, c := sweepReconciler(
		[]client.Object{&f.intCert, &f.intSecret, &f.intIssuer, &inFlight, &inFlightSecret,
			&notReady, &notReadySecret, pkir},
		[]client.Object{pkir, &inFlight, &notReady},
	)

	if _, err := r.reconcileIdleIntermediate(context.Background(), pkir); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if cond := issuingCondition(t, c, "in-flight", "kube-system"); cond == nil || cond.Reason != "Renewing" {
		t.Errorf("in-flight child must be left to cert-manager, got %+v", cond)
	}
	if cond := issuingCondition(t, c, "not-ready", "kube-system"); cond != nil {
		t.Errorf("not-Ready child must not be re-triggered, got Issuing=%s", cond.Status)
	}
}

// An Issuer in another namespace using the same Secret NAME is a different CA; its
// certificates legitimately carry a different AKID and must never be re-issued.
func TestReconcileIdleIntermediate_SameSecretNameOtherNamespace_NotTriggered(t *testing.T) {
	f := newStaleSweepFixture(t)
	otherPEM, _, otherKey := mustGenerateTestCAWithSKID(t, time.Now().Add(-time.Hour), []byte{0x0c, 0x03})
	foreignLeafPEM := mustGenerateSignedCert(t, otherPEM, otherKey, time.Now().Add(-time.Hour))

	foreignIssuer := newTestIssuer("lookalike", "team-a", "int-ca-secret")
	leaf, leafSecret := childCert("foreign", "team-a", "lookalike", issuerKindIssuer, foreignLeafPEM)

	pkir := buildIntermediatePKIR()
	pkir.Status.Phase = platformv1alpha1.PhaseIdle
	pkir.Status.CurrentSKID = f.intSKID

	r, c := sweepReconciler(
		[]client.Object{&f.intCert, &f.intSecret, &foreignIssuer, &leaf, &leafSecret, pkir},
		[]client.Object{pkir, &leaf},
	)

	if _, err := r.reconcileIdleIntermediate(context.Background(), pkir); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if cond := issuingCondition(t, c, "foreign", "team-a"); cond != nil {
		t.Errorf("certificate from a different CA must not be re-issued, got Issuing=%s", cond.Status)
	}
}

// Grandchildren chain to their own parent CA and correctly carry that CA's
// AKID; they belong to that CA's own sweep, not this one.
func TestReconcileIdleIntermediate_Grandchild_NotJudgedAgainstThisCA(t *testing.T) {
	f := newStaleSweepFixture(t)
	now := time.Now()

	tier2PEM, _, tier2Key := mustGenerateTestCAWithSKID(t, now.Add(-time.Hour), []byte{0x0d, 0x04})
	tier2, tier2Secret := childCert("ns-ca", "gateway", "int-issuer", issuerKindClusterIssuer,
		mustGenerateSignedCert(t, f.newPEM, f.newKey, now.Add(-time.Hour)))
	tier2.Spec.IsCA = true
	tier2Issuer := newTestIssuer("ns-ca-issuer", "gateway", tier2.Spec.SecretName)
	grandchild, grandchildSecret := childCert("wildcard", "gateway", "ns-ca-issuer", issuerKindIssuer,
		mustGenerateSignedCert(t, tier2PEM, tier2Key, now.Add(-time.Hour)))

	pkir := buildIntermediatePKIR()
	pkir.Status.Phase = platformv1alpha1.PhaseIdle
	pkir.Status.CurrentSKID = f.intSKID

	r, c := sweepReconciler(
		[]client.Object{&f.intCert, &f.intSecret, &f.intIssuer, &tier2, &tier2Secret, &tier2Issuer,
			&grandchild, &grandchildSecret, pkir},
		[]client.Object{pkir, &tier2, &grandchild},
	)

	if _, err := r.reconcileIdleIntermediate(context.Background(), pkir); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if cond := issuingCondition(t, c, "ns-ca", "gateway"); cond != nil {
		t.Errorf("current tier-2 CA must not be re-issued, got Issuing=%s", cond.Status)
	}
	if cond := issuingCondition(t, c, "wildcard", "gateway"); cond != nil {
		t.Errorf("grandchild must not be judged against the tier-1 SKID, got Issuing=%s", cond.Status)
	}
}

// The same gap one level up: an intermediate still signed by a previous root
// key. Re-issuing it rotates the intermediate, which cascades to its leaves
// through the IntermediateCA state machine.
func TestSweepStaleDirectChildren_RootCA_StaleIntermediate_Triggered(t *testing.T) {
	now := time.Now()
	oldRootPEM, _, oldRootKey := mustGenerateTestCAWithSKID(t, now.Add(-400*24*time.Hour), []byte{0x01})
	rootPEM, rootSKID, _ := mustGenerateTestCAWithSKID(t, now.Add(-10*24*time.Hour), []byte{0x02})

	rootCert := cmv1.Certificate{
		ObjectMeta: metav1.ObjectMeta{Name: "root-ca", Namespace: "cert-manager"},
		Spec: cmv1.CertificateSpec{
			SecretName: "root-ca-secret", IsCA: true,
			IssuerRef: cmmeta.IssuerReference{Name: "selfsigned", Kind: issuerKindClusterIssuer},
		},
		Status: cmv1.CertificateStatus{Conditions: readyConditions()},
	}
	rootSecret := corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{Name: "root-ca-secret", Namespace: "cert-manager"},
		Data:       map[string][]byte{"tls.crt": rootPEM},
	}
	rootIssuer := newTestClusterIssuer("root-issuer", "root-ca-secret")
	intermediate, intSecret := childCert("int-ca", "cert-manager", "root-issuer", issuerKindClusterIssuer,
		mustGenerateSignedCert(t, oldRootPEM, oldRootKey, now.Add(-300*24*time.Hour)))
	intermediate.Spec.IsCA = true

	pkir := buildRootPKIR()
	r, c := sweepReconciler(
		[]client.Object{&rootCert, &rootSecret, &rootIssuer, &intermediate, &intSecret, pkir},
		[]client.Object{pkir, &intermediate},
	)

	triggered, err := r.sweepStaleDirectChildren(context.Background(), pkir, &rootCert, rootSKID)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if triggered != 1 {
		t.Errorf("expected 1 stale intermediate triggered, got %d", triggered)
	}
	if cond := issuingCondition(t, c, "int-ca", "cert-manager"); cond == nil || cond.Status != cmmeta.ConditionTrue {
		t.Errorf("expected stale intermediate to be re-issued, got %v", cond)
	}
}
