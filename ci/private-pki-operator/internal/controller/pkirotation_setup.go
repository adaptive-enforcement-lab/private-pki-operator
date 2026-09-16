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

	cmv1 "github.com/cert-manager/cert-manager/pkg/apis/certmanager/v1"
	trustv1alpha1 "github.com/cert-manager/trust-manager/pkg/apis/trust/v1alpha1"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/types"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/builder"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/handler"
	"sigs.k8s.io/controller-runtime/pkg/predicate"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"

	platformv1alpha1 "github.com/adaptive-enforcement-lab/private-pki-operator/ci/private-pki-operator/api/v1alpha1"
)

// Manager registration and the event sources that map watched objects back to
// the PKIRotation they belong to.

// SetupWithManager registers the four watches and wires the controller.
func (r *PKIRotationReconciler) SetupWithManager(mgr ctrl.Manager) error {
	// Watch 1: CertificateRequest creation — triggers Idle -> PreservingOldRoot.
	// cert-manager stores cert-manager.io/certificate-name in ANNOTATIONS (not labels).
	certificateRequestPredicate := predicate.NewPredicateFuncs(func(obj client.Object) bool {
		annotations := obj.GetAnnotations()
		return annotations != nil && annotations[cmv1.CertificateNameKey] != ""
	})

	// Watch 2 & 3: Certificate status changes (root CA and intermediates).
	// cert-manager renews certs by writing a new Secret but does NOT change the
	// Certificate spec (generation stays the same). ResourceVersionChangedPredicate
	// fires on any update including status, so we catch renewal completions.
	certificatePredicate := predicate.ResourceVersionChangedPredicate{}

	return ctrl.NewControllerManagedBy(mgr).
		// Primary resource.
		For(&platformv1alpha1.PKIRotation{}).
		// Watch 1: CertificateRequest CREATE in any namespace (filtered in reconciler).
		Watches(
			&cmv1.CertificateRequest{}, handler.EnqueueRequestsFromMapFunc(r.certificateRequestToPKIRotations),
			builder.WithPredicates(certificateRequestPredicate),
		).
		// Watch 2: Root CA Certificate changes (renewal detection).
		// Watch 3: Any isCA Certificate change cluster-wide — fires when namespace
		// intermediates are re-issued during AwaitingReissuance/VerifyingChain.
		// Certificates are cached cluster-wide (see cache.ByObject in cmd/main.go).
		Watches(
			&cmv1.Certificate{}, handler.EnqueueRequestsFromMapFunc(r.certificateToPKIRotations),
			builder.WithPredicates(certificatePredicate),
		).
		// Watch 4: trust-manager Bundle changes.
		Watches(&trustv1alpha1.Bundle{}, handler.EnqueueRequestsFromMapFunc(r.bundleToPKIRotations)).
		// Watch 5: Intermediate CA Secret changes — enqueues matching IntermediateCA PKIRotation.
		// Fires when cert-manager rotates an intermediate CA's private key and writes a new Secret.
		Watches(
			&corev1.Secret{}, handler.EnqueueRequestsFromMapFunc(r.intermediateSecretMapper),
			builder.WithPredicates(predicate.ResourceVersionChangedPredicate{}),
		).
		Named("pkirotation").
		Complete(r)
}

// pkiRotationsMatching lists every PKIRotation and returns one reconcile request
// per object the predicate accepts. A List failure yields no requests: the watch
// is an optimisation over the phase requeue, never the only path back in.
func (r *PKIRotationReconciler) pkiRotationsMatching(
	ctx context.Context, match func(pkir *platformv1alpha1.PKIRotation) bool,
) []reconcile.Request {
	var list platformv1alpha1.PKIRotationList
	if err := r.List(ctx, &list); err != nil {
		return nil
	}
	var reqs []reconcile.Request
	for i := range list.Items {
		if match(&list.Items[i]) {
			reqs = append(reqs, reconcile.Request{
				NamespacedName: types.NamespacedName{Name: list.Items[i].Name},
			})
		}
	}
	return reqs
}

// certificateRequestToPKIRotations maps a CertificateRequest to the rotations
// that own the root CA it was raised for. The object is the CertificateRequest,
// not the Certificate, so the Certificate name comes from the cert-manager
// ANNOTATION rather than from the object's own name.
func (r *PKIRotationReconciler) certificateRequestToPKIRotations(
	ctx context.Context, obj client.Object,
) []reconcile.Request {
	certName, ok := obj.GetAnnotations()[cmv1.CertificateNameKey]
	if !ok {
		return nil
	}
	return r.pkiRotationsMatching(ctx, func(pkir *platformv1alpha1.PKIRotation) bool {
		return pkir.Spec.RootCA.CertificateName == certName &&
			pkir.Spec.RootCA.CertificateNamespace == obj.GetNamespace()
	})
}

// certificateToPKIRotations maps a Certificate to the rotations that declared it
// as their root CA. When it is not a declared root, it instead wakes every
// rotation mid-flight, so AwaitingReissuance and VerifyingChain pick up
// intermediate and leaf re-issuances promptly rather than waiting out the phase
// requeue.
func (r *PKIRotationReconciler) certificateToPKIRotations(
	ctx context.Context, obj client.Object,
) []reconcile.Request {
	reqs := r.pkiRotationsMatching(ctx, func(pkir *platformv1alpha1.PKIRotation) bool {
		return pkir.Spec.RootCA.CertificateName == obj.GetName() &&
			pkir.Spec.RootCA.CertificateNamespace == obj.GetNamespace()
	})
	if len(reqs) > 0 {
		return reqs
	}
	return r.pkiRotationsMatching(ctx, func(pkir *platformv1alpha1.PKIRotation) bool {
		return pkir.Status.Phase == platformv1alpha1.PhaseAwaitingReissuance ||
			pkir.Status.Phase == platformv1alpha1.PhaseVerifyingChain
	})
}

// bundleToPKIRotations maps a trust-manager Bundle to the rotations that
// distribute their trust anchors through it.
func (r *PKIRotationReconciler) bundleToPKIRotations(ctx context.Context, obj client.Object) []reconcile.Request {
	return r.pkiRotationsMatching(ctx, func(pkir *platformv1alpha1.PKIRotation) bool {
		return pkir.Spec.TrustBundle.Name == obj.GetName()
	})
}
