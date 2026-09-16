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
	"k8s.io/client-go/tools/record"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"

	platformv1alpha1 "github.com/adaptive-enforcement-lab/private-pki-operator/ci/private-pki-operator/api/v1alpha1"
)

// TestIntermediateSecretMapper_MatchingSecret verifies that when a Secret change event
// matches the SecretName of an IntermediateCA PKIRotation's Certificate, the mapper
// returns a reconcile.Request for that PKIRotation.
func TestIntermediateSecretMapper_MatchingSecret(t *testing.T) {
	cert := &cmv1.Certificate{
		ObjectMeta: metav1.ObjectMeta{Name: "int-ca", Namespace: "cert-manager"},
		Spec:       cmv1.CertificateSpec{SecretName: "int-ca-secret", IsCA: true},
	}

	pkir := buildIntermediatePKIR()
	// buildIntermediatePKIR sets CertificateName="int-ca", CertificateNamespace="cert-manager"

	c := fake.NewClientBuilder().
		WithScheme(makeCMScheme()).
		WithObjects(cert, pkir).
		Build()
	r := &PKIRotationReconciler{
		Client:   c,
		Scheme:   makeCMScheme(),
		Recorder: record.NewFakeRecorder(10),
	}

	secret := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{Name: "int-ca-secret", Namespace: "cert-manager"},
	}

	requests := r.intermediateSecretMapper(context.Background(), secret)

	if len(requests) != 1 {
		t.Fatalf("expected 1 reconcile.Request, got %d", len(requests))
	}
	if requests[0].Name != pkir.Name {
		t.Errorf("expected request for PKIRotation %q, got %q", pkir.Name, requests[0].Name)
	}
}

// TestIntermediateSecretMapper_NoMatch verifies that when a Secret change event does
// not match the SecretName of any IntermediateCA PKIRotation, the mapper returns nil.
func TestIntermediateSecretMapper_NoMatch(t *testing.T) {
	cert := &cmv1.Certificate{
		ObjectMeta: metav1.ObjectMeta{Name: "int-ca", Namespace: "cert-manager"},
		Spec:       cmv1.CertificateSpec{SecretName: "int-ca-secret", IsCA: true},
	}

	pkir := buildIntermediatePKIR()

	c := fake.NewClientBuilder().
		WithScheme(makeCMScheme()).
		WithObjects(cert, pkir).
		Build()
	r := &PKIRotationReconciler{
		Client:   c,
		Scheme:   makeCMScheme(),
		Recorder: record.NewFakeRecorder(10),
	}

	// Different secret name — should not match.
	secret := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{Name: "some-other-secret", Namespace: "cert-manager"},
	}

	requests := r.intermediateSecretMapper(context.Background(), secret)

	if len(requests) != 0 {
		t.Errorf("expected 0 reconcile.Requests, got %d: %v", len(requests), requests)
	}
}

// TestIntermediateSecretMapper_NamespaceMismatch verifies that a Secret with the correct
// name but wrong namespace does not enqueue the IntermediateCA PKIRotation.
func TestIntermediateSecretMapper_NamespaceMismatch(t *testing.T) {
	cert := &cmv1.Certificate{
		ObjectMeta: metav1.ObjectMeta{Name: "int-ca", Namespace: "cert-manager"},
		Spec:       cmv1.CertificateSpec{SecretName: "int-ca-secret", IsCA: true},
	}

	pkir := buildIntermediatePKIR()

	c := fake.NewClientBuilder().
		WithScheme(makeCMScheme()).
		WithObjects(cert, pkir).
		Build()
	r := &PKIRotationReconciler{
		Client:   c,
		Scheme:   makeCMScheme(),
		Recorder: record.NewFakeRecorder(10),
	}

	// Same secret name, but wrong namespace — the namespace guard must block this.
	secret := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{Name: "int-ca-secret", Namespace: "WRONG-NS"},
	}

	requests := r.intermediateSecretMapper(context.Background(), secret)

	if len(requests) != 0 {
		t.Errorf("expected 0 reconcile.Requests for namespace mismatch, got %d: %v", len(requests), requests)
	}
}

// TestIntermediateSecretMapper_CertificateNotFound verifies that when the Certificate
// referenced by an IntermediateCA PKIRotation does not exist, the mapper silently skips
// the PKIRotation and returns no requests (no panic).
func TestIntermediateSecretMapper_CertificateNotFound(t *testing.T) {
	// PKIRotation whose Certificate does NOT exist in the fake client.
	pkir := buildIntermediatePKIR()

	c := fake.NewClientBuilder().
		WithScheme(makeCMScheme()).
		WithObjects(pkir). // no Certificate registered
		Build()
	r := &PKIRotationReconciler{
		Client:   c,
		Scheme:   makeCMScheme(),
		Recorder: record.NewFakeRecorder(10),
	}

	secret := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{Name: "int-ca-secret", Namespace: "cert-manager"},
	}

	requests := r.intermediateSecretMapper(context.Background(), secret)

	if len(requests) != 0 {
		t.Errorf("expected 0 reconcile.Requests when Certificate not found, got %d: %v", len(requests), requests)
	}
}

// TestIntermediateSecretMapper_MultipleIntermediates_OnlyMatchingEnqueued verifies that
// when two IntermediateCA PKIRotations exist, only the one whose Certificate SecretName
// matches the incoming Secret is enqueued.
func TestIntermediateSecretMapper_MultipleIntermediates_OnlyMatchingEnqueued(t *testing.T) {
	certA := &cmv1.Certificate{
		ObjectMeta: metav1.ObjectMeta{Name: "int-ca-a", Namespace: "cert-manager"},
		Spec:       cmv1.CertificateSpec{SecretName: "secret-A", IsCA: true},
	}
	certB := &cmv1.Certificate{
		ObjectMeta: metav1.ObjectMeta{Name: "int-ca-b", Namespace: "cert-manager"},
		Spec:       cmv1.CertificateSpec{SecretName: "secret-B", IsCA: true},
	}

	pkirA := &platformv1alpha1.PKIRotation{
		ObjectMeta: metav1.ObjectMeta{Name: "int-rotation-a"},
		Spec: platformv1alpha1.PKIRotationSpec{
			Role: platformv1alpha1.RoleIntermediateCA,
			IntermediateCA: &platformv1alpha1.IntermediateCARef{
				CertificateName:      "int-ca-a",
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
	pkirB := &platformv1alpha1.PKIRotation{
		ObjectMeta: metav1.ObjectMeta{Name: "int-rotation-b"},
		Spec: platformv1alpha1.PKIRotationSpec{
			Role: platformv1alpha1.RoleIntermediateCA,
			IntermediateCA: &platformv1alpha1.IntermediateCARef{
				CertificateName:      "int-ca-b",
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

	c := fake.NewClientBuilder().
		WithScheme(makeCMScheme()).
		WithObjects(certA, certB, pkirA, pkirB).
		Build()
	r := &PKIRotationReconciler{
		Client:   c,
		Scheme:   makeCMScheme(),
		Recorder: record.NewFakeRecorder(10),
	}

	// Event for "secret-A" — only pkirA should be enqueued.
	secret := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{Name: "secret-A", Namespace: "cert-manager"},
	}

	requests := r.intermediateSecretMapper(context.Background(), secret)

	if len(requests) != 1 {
		t.Fatalf("expected 1 reconcile.Request, got %d: %v", len(requests), requests)
	}
	if requests[0].Name != pkirA.Name {
		t.Errorf("expected request for PKIRotation %q, got %q", pkirA.Name, requests[0].Name)
	}
}

// TestIntermediateSecretMapper_SkipsRootCACRs verifies that RootCA PKIRotation CRs are
// never enqueued by the intermediate Secret mapper, even when a secret with a matching
// name exists in the namespace.
func TestIntermediateSecretMapper_SkipsRootCACRs(t *testing.T) {
	// A RootCA PKIRotation — no spec.intermediateCA.
	rootPKIR := &platformv1alpha1.PKIRotation{
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
	}

	c := fake.NewClientBuilder().
		WithScheme(makeCMScheme()).
		WithObjects(rootPKIR).
		Build()
	r := &PKIRotationReconciler{
		Client:   c,
		Scheme:   makeCMScheme(),
		Recorder: record.NewFakeRecorder(10),
	}

	// Any secret — the RootCA CR has no spec.intermediateCA so it must not match.
	secret := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{Name: "root-ca-secret", Namespace: "cert-manager"},
	}

	requests := r.intermediateSecretMapper(context.Background(), secret)

	if len(requests) != 0 {
		t.Errorf("expected 0 reconcile.Requests for RootCA CR, got %d: %v", len(requests), requests)
	}
}
