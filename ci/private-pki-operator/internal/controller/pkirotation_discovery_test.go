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
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/client-go/tools/record"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"

	platformv1alpha1 "github.com/adaptive-enforcement-lab/private-pki-operator/ci/private-pki-operator/api/v1alpha1"
)

// makePKIScheme returns a scheme with corev1 + platform types.
func makePKIScheme() *runtime.Scheme {
	s := runtime.NewScheme()
	_ = corev1.AddToScheme(s)
	_ = platformv1alpha1.AddToScheme(s)
	return s
}

// makeCMScheme returns a scheme with corev1 + cert-manager + platform types for discovery tests.
func makeCMScheme() *runtime.Scheme {
	s := makePKIScheme()
	_ = cmv1.AddToScheme(s)
	return s
}

// newTestCA builds a cert-manager Certificate with isCA=true.
func newTestCA(name, ns, secretName, issuerName, issuerKind string) cmv1.Certificate {
	return cmv1.Certificate{
		ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: ns},
		Spec: cmv1.CertificateSpec{
			SecretName: secretName,
			IsCA:       true,
			IssuerRef: cmmeta.IssuerReference{
				Name: issuerName,
				Kind: issuerKind,
			},
		},
		Status: cmv1.CertificateStatus{
			Conditions: []cmv1.CertificateCondition{
				{Type: cmv1.CertificateConditionReady, Status: cmmeta.ConditionTrue},
			},
		},
	}
}

// newTestLeaf builds a cert-manager Certificate with isCA=false.
func newTestLeaf(name, ns, issuerName, issuerKind string) cmv1.Certificate {
	return cmv1.Certificate{
		ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: ns},
		Spec: cmv1.CertificateSpec{
			SecretName: name + "-tls",
			IsCA:       false,
			IssuerRef: cmmeta.IssuerReference{
				Name: issuerName,
				Kind: issuerKind,
			},
		},
	}
}

// newTestClusterIssuer builds a ClusterIssuer backed by a given Secret name.
func newTestClusterIssuer(name, secretName string) cmv1.ClusterIssuer {
	return cmv1.ClusterIssuer{
		ObjectMeta: metav1.ObjectMeta{Name: name},
		Spec:       cmv1.IssuerSpec{IssuerConfig: cmv1.IssuerConfig{CA: &cmv1.CAIssuer{SecretName: secretName}}},
	}
}

// newTestIssuer builds a namespace-scoped Issuer backed by a given Secret name.
func newTestIssuer(name, ns, secretName string) cmv1.Issuer {
	return cmv1.Issuer{
		ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: ns},
		Spec:       cmv1.IssuerSpec{IssuerConfig: cmv1.IssuerConfig{CA: &cmv1.CAIssuer{SecretName: secretName}}},
	}
}

// TestDiscoverDownstream_ClusterIssuerAnchor verifies BFS finds CA cert and leaf
// when the anchor is a ClusterIssuer.
func TestDiscoverDownstream_ClusterIssuerAnchor(t *testing.T) {
	ci := newTestClusterIssuer("int-issuer", "int-ca-secret")
	intCA := newTestCA("int-ca", "cert-manager", "int-ca-secret", "int-issuer", "ClusterIssuer")
	leaf := newTestLeaf("leaf", "cert-manager", "int-issuer", "ClusterIssuer")

	// int-ca is a CA but no Issuer is backed by "int-ca-secret", so recursion terminates.
	c := fake.NewClientBuilder().
		WithScheme(makeCMScheme()).
		WithObjects(&ci, &intCA, &leaf).
		Build()
	r := &PKIRotationReconciler{Client: c, Scheme: makeCMScheme(), Recorder: record.NewFakeRecorder(10)}

	anchor := issuerAnchor{Name: "int-issuer", Kind: "ClusterIssuer"}
	cas, leaves, err := r.discoverDownstream(context.Background(), anchor)
	if err != nil {
		t.Fatalf("discoverDownstream: %v", err)
	}
	if len(cas) != 1 || cas[0].Name != "int-ca" {
		t.Errorf("expected 1 CA cert 'int-ca', got %v", certNamesForTest(cas))
	}
	if len(leaves) != 1 || leaves[0].Name != "leaf" {
		t.Errorf("expected 1 leaf 'leaf', got %v", certNamesForTest(leaves))
	}
}

// TestDiscoverDownstream_Recursive verifies BFS recurses into tier-2 via a namespace Issuer.
func TestDiscoverDownstream_Recursive(t *testing.T) {
	ci := newTestClusterIssuer("tier1-issuer", "tier1-secret")
	tier1CA := newTestCA("tier1-ca", "cert-manager", "tier1-secret", "tier1-issuer", "ClusterIssuer")
	tier2Issuer := newTestIssuer("tier2-issuer", "app", "tier1-secret")
	tier2CA := newTestCA("tier2-ca", "app", "tier2-secret", "tier2-issuer", "Issuer")
	appLeaf := newTestLeaf("app-leaf", "app", "tier2-issuer", "Issuer")

	c := fake.NewClientBuilder().
		WithScheme(makeCMScheme()).
		WithObjects(&ci, &tier1CA, &tier2Issuer, &tier2CA, &appLeaf).
		Build()
	r := &PKIRotationReconciler{Client: c, Scheme: makeCMScheme(), Recorder: record.NewFakeRecorder(10)}

	anchor := issuerAnchor{Name: "tier1-issuer", Kind: "ClusterIssuer"}
	cas, leaves, err := r.discoverDownstream(context.Background(), anchor)
	if err != nil {
		t.Fatalf("discoverDownstream: %v", err)
	}

	if len(cas) != 2 {
		t.Errorf("expected 2 CA certs (tier1-ca + tier2-ca), got %v", certNamesForTest(cas))
	}
	if len(leaves) != 1 || leaves[0].Name != "app-leaf" {
		t.Errorf("expected 1 leaf 'app-leaf', got %v", certNamesForTest(leaves))
	}
}

// TestDiscoverDownstream_Empty verifies no-op when anchor has no downstream certs.
func TestDiscoverDownstream_Empty(t *testing.T) {
	ci := newTestClusterIssuer("orphan-issuer", "orphan-secret")

	c := fake.NewClientBuilder().
		WithScheme(makeCMScheme()).
		WithObjects(&ci).
		Build()
	r := &PKIRotationReconciler{Client: c, Scheme: makeCMScheme(), Recorder: record.NewFakeRecorder(10)}

	anchor := issuerAnchor{Name: "orphan-issuer", Kind: "ClusterIssuer"}
	cas, leaves, err := r.discoverDownstream(context.Background(), anchor)
	if err != nil {
		t.Fatalf("discoverDownstream: %v", err)
	}
	if len(cas) != 0 || len(leaves) != 0 {
		t.Errorf("expected empty results, got cas=%v leaves=%v", certNamesForTest(cas), certNamesForTest(leaves))
	}
}

// TestDiscoverDownstream_NamespaceIssuerAnchor verifies BFS works when the anchor is
// a namespace-scoped Issuer (not ClusterIssuer).
func TestDiscoverDownstream_NamespaceIssuerAnchor(t *testing.T) {
	issuer := newTestIssuer("app-issuer", "app", "app-ca-secret")
	leaf := newTestLeaf("app-leaf", "app", "app-issuer", "Issuer")

	c := fake.NewClientBuilder().
		WithScheme(makeCMScheme()).
		WithObjects(&issuer, &leaf).
		Build()
	r := &PKIRotationReconciler{Client: c, Scheme: makeCMScheme(), Recorder: record.NewFakeRecorder(10)}

	anchor := issuerAnchor{Name: "app-issuer", Kind: "Issuer", Namespace: "app"}
	cas, leaves, err := r.discoverDownstream(context.Background(), anchor)
	if err != nil {
		t.Fatalf("discoverDownstream: %v", err)
	}
	if len(cas) != 0 {
		t.Errorf("expected no CA certs, got %v", certNamesForTest(cas))
	}
	if len(leaves) != 1 || leaves[0].Name != "app-leaf" {
		t.Errorf("expected 1 leaf 'app-leaf', got %v", certNamesForTest(leaves))
	}
}

// TestDiscoverDownstream_NoCycleWhenAnchorIsParentIssuer verifies that when a CA cert is
// signed by a ClusterIssuer whose secretName equals the CA cert's own secretName
// (an adversarial/misconfigured topology), the BFS terminates without looping.
//
// Fixture: ClusterIssuer "ca-issuer" backed by "ca-secret".
//
//	CA cert "ca" in cert-manager signed by "ca-issuer", stores to "ca-secret".
//	This means findIssuersForCACert("ca") would naively return "ca-issuer" again,
//	causing infinite recursion. The ancestor-exclusion guard must prevent this.
func TestDiscoverDownstream_NoCycleWhenAnchorIsParentIssuer(t *testing.T) {
	ci := newTestClusterIssuer("ca-issuer", "ca-secret")
	// CA cert signed by "ca-issuer", stores into "ca-secret".
	// findIssuersForCACert would find "ca-issuer" (backed by "ca-secret") without the guard.
	caCert := newTestCA("ca", "cert-manager", "ca-secret", "ca-issuer", "ClusterIssuer")

	c := fake.NewClientBuilder().
		WithScheme(makeCMScheme()).
		WithObjects(&ci, &caCert).
		Build()
	r := &PKIRotationReconciler{Client: c, Scheme: makeCMScheme(), Recorder: record.NewFakeRecorder(10)}

	anchor := issuerAnchor{Name: "ca-issuer", Kind: "ClusterIssuer"}

	// This must return without looping. If the ancestor-exclusion guard is absent, this hangs.
	done := make(chan struct{})
	var cas []cmv1.Certificate
	var err error
	go func() {
		cas, _, err = r.discoverDownstream(context.Background(), anchor)
		close(done)
	}()

	select {
	case <-done:
	case <-time.After(3 * time.Second):
		t.Fatal("discoverDownstream did not terminate — ancestor-exclusion guard may be missing")
	}

	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	// The CA cert itself is found (it's signed by ca-issuer), but the loop stops there.
	if len(cas) != 1 || cas[0].Name != "ca" {
		t.Errorf("expected 1 CA cert 'ca', got %v", certNamesForTest(cas))
	}
}

// certNamesForTest extracts "namespace/name" strings for use in error messages.
func certNamesForTest(certs []cmv1.Certificate) []string {
	names := make([]string, len(certs))
	for i, c := range certs {
		names[i] = c.Namespace + "/" + c.Name
	}
	return names
}

// Ensure platformv1alpha1 import is used (makePKIScheme references it).
var _ = platformv1alpha1.GroupVersion
