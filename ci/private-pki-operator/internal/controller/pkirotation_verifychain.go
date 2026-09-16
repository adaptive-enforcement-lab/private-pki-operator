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
	"fmt"
	"time"

	cmv1 "github.com/cert-manager/cert-manager/pkg/apis/certmanager/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	ctrl "sigs.k8s.io/controller-runtime"
	logf "sigs.k8s.io/controller-runtime/pkg/log"

	platformv1alpha1 "github.com/adaptive-enforcement-lab/private-pki-operator/ci/private-pki-operator/api/v1alpha1"
)

// Chain verification for the root-tier rotation. Each helper returns a non-nil
// *ctrl.Result when the caller must return it: verification has not succeeded
// and the rotation stays in VerifyingChain.

// derefResult turns the "return this result now" convention used by the verify*
// helpers back into a value. A nil result means "keep going", which only ever
// reaches here alongside a non-nil error.
func derefResult(res *ctrl.Result) ctrl.Result {
	if res == nil {
		return ctrl.Result{}
	}
	return *res
}

// verifyTier1Chain checks every cluster intermediate chains to the new root. A
// non-nil result means the caller must return it: verification has not
// succeeded and the rotation stays in VerifyingChain.
func (r *PKIRotationReconciler) verifyTier1Chain(
	ctx context.Context, pkir *platformv1alpha1.PKIRotation, tier1 []cmv1.Certificate,
) (*ctrl.Result, error) {
	for _, cert := range tier1 {
		akid, err := r.certificateAKID(ctx, &cert)
		if err != nil {
			r.setCondition(pkir, platformv1alpha1.ConditionChainVerified, metav1.ConditionFalse,
				platformv1alpha1.ReasonSecretReadFailed, err.Error())
			r.updateConditionStatus(ctx, pkir, "intermediate CA Secret unreadable")
			return &ctrl.Result{}, fmt.Errorf("verifying chain for %s/%s: %w", cert.Namespace, cert.Name, err)
		}
		if akid == "" || akid != pkir.Status.CurrentSKID {
			msg := fmt.Sprintf("%s/%s: AKID %s does not match new root SKID %s",
				cert.Namespace, cert.Name, akid, pkir.Status.CurrentSKID)
			r.setCondition(pkir, platformv1alpha1.ConditionChainVerified, metav1.ConditionFalse,
				platformv1alpha1.ReasonAKIDMismatch, msg)
			r.Recorder.Event(pkir, corev1.EventTypeWarning, "ChainVerificationFailed", msg)
			r.updateConditionStatus(ctx, pkir, "chain not yet verified")
			return &ctrl.Result{RequeueAfter: 30 * time.Second}, nil
		}
	}
	return nil, nil
}

// verifyTier2Chain checks every namespace intermediate was re-issued after the
// cluster intermediate it hangs off, re-triggering any that was not. A non-nil
// result means the caller must return it.
func (r *PKIRotationReconciler) verifyTier2Chain(
	ctx context.Context, pkir *platformv1alpha1.PKIRotation, tier2 []cmv1.Certificate, clusterIntNotBefore time.Time,
) *ctrl.Result {
	log := logf.FromContext(ctx)
	for _, cert := range tier2 {
		if isCertificateResourceReady(&cert) && cert.Status.NotBefore != nil &&
			cert.Status.NotBefore.After(clusterIntNotBefore) {
			continue
		}
		if !isCertificateIssuingTrue(&cert) {
			log.Info("namespace intermediate not yet reissued after cluster intermediate rotation — re-triggering",
				"certificate", fmt.Sprintf("%s/%s", cert.Namespace, cert.Name))
			_ = r.triggerReissuance(ctx, &cert)
		}
		msg := fmt.Sprintf("%s/%s: namespace intermediate not yet reissued after cluster intermediate rotation",
			cert.Namespace, cert.Name)
		r.setCondition(pkir, platformv1alpha1.ConditionChainVerified, metav1.ConditionFalse,
			platformv1alpha1.ReasonAKIDMismatch, msg)
		r.Recorder.Event(pkir, corev1.EventTypeWarning, "ChainVerificationFailed", msg)
		r.updateConditionStatus(ctx, pkir, "chain not yet verified")
		return &ctrl.Result{RequeueAfter: 10 * time.Second}
	}
	return nil
}

// verifyLeafChain checks every leaf was re-issued after its DIRECT parent
// intermediate, re-triggering any that was not. A non-nil result means the
// caller must return it.
//
// The baseline is per-namespace, not the global maximum across all
// intermediates: a global maximum incorrectly fails leaves that are properly
// chained to their own parent but share a cluster with an unrelated
// intermediate reissued later — for instance because its Secret was
// independently deleted mid-rotation. Leaves issued directly by a tier-1
// ClusterIssuer fall back to clusterIntNotBefore.
func (r *PKIRotationReconciler) verifyLeafChain(
	ctx context.Context, pkir *platformv1alpha1.PKIRotation, leaves, tier2 []cmv1.Certificate,
	clusterIntNotBefore time.Time,
) *ctrl.Result {
	log := logf.FromContext(ctx)
	tier2NotBeforeByNS := make(map[string]time.Time, len(tier2))
	for _, c := range tier2 {
		if c.Status.NotBefore != nil {
			tier2NotBeforeByNS[c.Namespace] = c.Status.NotBefore.Time
		}
	}

	for i := range leaves {
		cert := &leaves[i]
		if !isCertificateResourceReady(cert) {
			log.Info("leaf cert re-issuance in progress",
				"certificate", fmt.Sprintf("%s/%s", cert.Namespace, cert.Name))
			msg := fmt.Sprintf("%s/%s: leaf cert re-issuance in progress", cert.Namespace, cert.Name)
			r.setCondition(pkir, platformv1alpha1.ConditionChainVerified, metav1.ConditionFalse,
				"LeafReissuancePending", msg)
			r.updateConditionStatus(ctx, pkir, "chain not yet verified")
			return &ctrl.Result{RequeueAfter: 30 * time.Second}
		}
		parentNotBefore := clusterIntNotBefore
		if t, ok := tier2NotBeforeByNS[cert.Namespace]; ok {
			parentNotBefore = t
		}
		if cert.Status.NotBefore != nil && !cert.Status.NotBefore.Time.Before(parentNotBefore) {
			continue
		}
		if !isCertificateIssuingTrue(cert) {
			log.Info("leaf cert not yet reissued after intermediate rotation — re-triggering",
				"certificate", fmt.Sprintf("%s/%s", cert.Namespace, cert.Name),
				"leafNotBefore", cert.Status.NotBefore,
				"parentNotBefore", parentNotBefore)
			// Re-trigger reissuance: cert-manager does not spontaneously reissue
			// valid certs, so if the timing check fails we must trigger again.
			_ = r.triggerReissuance(ctx, cert)
		}
		msg := fmt.Sprintf("%s/%s: leaf cert not yet reissued after intermediate CA rotation",
			cert.Namespace, cert.Name)
		r.setCondition(pkir, platformv1alpha1.ConditionChainVerified, metav1.ConditionFalse,
			"LeafReissuancePending", msg)
		r.updateConditionStatus(ctx, pkir, "chain not yet verified")
		return &ctrl.Result{RequeueAfter: 10 * time.Second}
	}
	return nil
}
