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
	"sigs.k8s.io/controller-runtime/pkg/client"
	logf "sigs.k8s.io/controller-runtime/pkg/log"

	platformv1alpha1 "github.com/adaptive-enforcement-lab/private-pki-operator/ci/private-pki-operator/api/v1alpha1"
)

// Phase handlers for the root-tier rotation state machine. Each returns the
// ctrl.Result for its phase; Reconcile in pkirotation_controller.go dispatches
// to them and owns nothing else.

// reconcileIdle ensures the staging ConfigMap and trust Bundle exist, records
// the current root SKID, and waits. Transition to PreservingOldRoot occurs when:
//
//	(a) Watch 1 fires (CertificateRequest created) and the SKID is still unchanged, or
//	(b) the Secret SKID already differs from the stored snapshot (operator was down during renewal).
func (r *PKIRotationReconciler) reconcileIdle(
	ctx context.Context, pkir *platformv1alpha1.PKIRotation,
) (ctrl.Result, error) {
	log := logf.FromContext(ctx)

	// Ensure the staging ConfigMap and Bundle exist (idempotent — no-op if already correct).
	if err := r.ensureStagingConfigMap(ctx, pkir); err != nil {
		return ctrl.Result{}, fmt.Errorf("ensuring staging ConfigMap: %w", err)
	}
	if err := r.ensureBundle(ctx, pkir); err != nil {
		return ctrl.Result{}, fmt.Errorf("ensuring trust bundle: %w", err)
	}

	skid, err := r.currentRootSKID(ctx, pkir)
	if err != nil {
		return ctrl.Result{}, fmt.Errorf("reading root CA SKID: %w", err)
	}

	// (b) SKID already changed — cert was renewed while we were not watching.
	if pkir.Status.CurrentSKID != "" && pkir.Status.CurrentSKID != skid {
		log.Info("Root CA SKID changed; entering rotation", "oldSKID", pkir.Status.CurrentSKID, "newSKID", skid)
		pkir.Status.PreviousSKID = pkir.Status.CurrentSKID
		pkir.Status.CurrentSKID = skid
		return r.transitionTo(ctx, pkir, platformv1alpha1.PhasePreservingOldRoot, "SKIDChanged")
	}

	// First run: record baseline SKID and return — nothing else to do yet.
	if pkir.Status.CurrentSKID == "" {
		log.Info("Recording current root SKID", "skid", skid)
		pkir.Status.CurrentSKID = skid
		if err := r.Status().Update(ctx, pkir); err != nil {
			return ctrl.Result{}, fmt.Errorf("updating status with root SKID: %w", err)
		}
		if err := r.ensureIntermediateCACRs(ctx, pkir); err != nil {
			return ctrl.Result{}, fmt.Errorf("ensuring intermediate CA CRs: %w", err)
		}
		return ctrl.Result{}, nil
	}

	// (a) SKID unchanged — check for an active CertificateRequest (rotation is starting).
	active, err := r.hasActiveCertificateRequest(ctx, pkir)
	if err != nil {
		return ctrl.Result{}, fmt.Errorf("checking for active CertificateRequest: %w", err)
	}
	if active {
		log.Info("Active CertificateRequest detected; entering rotation", "previousSKID", skid)
		pkir.Status.PreviousSKID = skid
		return r.transitionTo(ctx, pkir, platformv1alpha1.PhasePreservingOldRoot, "CertificateRequestDetected")
	}

	// Auto-create child IntermediateCA PKIRotation CRs for every intermediate CA
	// discovered below the root CA's anchor. Idempotent — safe to call every reconcile.
	if err := r.ensureIntermediateCACRs(ctx, pkir); err != nil {
		return ctrl.Result{}, fmt.Errorf("ensuring intermediate CA CRs: %w", err)
	}

	return ctrl.Result{}, nil
}

// hasActiveCertificateRequest reports whether there is a pending (non-Ready)
// CertificateRequest for the root CA certificate.
// cert-manager stores cert-manager.io/certificate-name in ANNOTATIONS (not labels),
// so we list all CRs in the namespace and filter by annotation in code.
func (r *PKIRotationReconciler) hasActiveCertificateRequest(
	ctx context.Context, pkir *platformv1alpha1.PKIRotation,
) (bool, error) {
	var crList cmv1.CertificateRequestList
	if err := r.List(ctx, &crList,
		client.InNamespace(pkir.Spec.RootCA.CertificateNamespace),
	); err != nil {
		return false, fmt.Errorf("listing CertificateRequests: %w", err)
	}
	for i := range crList.Items {
		ann := crList.Items[i].GetAnnotations()
		if ann == nil || ann[cmv1.CertificateNameKey] != pkir.Spec.RootCA.CertificateName {
			continue
		}
		if !isCertificateRequestReady(&crList.Items[i]) {
			return true, nil
		}
	}
	return false, nil
}

// isCertificateRequestReady returns true when the CertificateRequest has a Ready=True condition.
func isCertificateRequestReady(cr *cmv1.CertificateRequest) bool {
	for _, cond := range cr.Status.Conditions {
		if string(cond.Type) == "Ready" && string(cond.Status) == "True" {
			return true
		}
	}
	return false
}

// reconcilePreservingOldRoot waits for the root CA Secret SKID to change,
// signalling that cert-manager has completed a key-rotating renewal. Reads the
// new cert to confirm the SKID has changed, then advances to DualTrustActive.
//
// Edge case — same-key renewal (rotationPolicy: Never):
// cert-manager renews the root cert validity without generating a new key, so
// the SKID never changes. When the renewal is complete (no active
// CertificateRequest remains) but the SKID is unchanged, no dual-trust window
// is needed — the chain is unaffected. The operator resets to Idle.
func (r *PKIRotationReconciler) reconcilePreservingOldRoot(
	ctx context.Context, pkir *platformv1alpha1.PKIRotation,
) (ctrl.Result, error) {
	log := logf.FromContext(ctx)

	skid, err := r.currentRootSKID(ctx, pkir)
	if err != nil {
		return ctrl.Result{}, fmt.Errorf("reading root CA SKID: %w", err)
	}
	if skid == pkir.Status.PreviousSKID {
		// SKID unchanged — either renewal is still in progress, or it completed
		// with the same key (rotationPolicy: Never). Distinguish the two cases.
		active, err := r.hasActiveCertificateRequest(ctx, pkir)
		if err != nil {
			return ctrl.Result{}, fmt.Errorf("checking for active CertificateRequest: %w", err)
		}
		if !active {
			// No active CertificateRequest and SKID unchanged: cert-manager renewed
			// the root cert validity with the same key. No dual-trust window needed.
			log.Info("Root CA renewed with same key (rotationPolicy=Never); aborting rotation", "skid", skid)
			pkir.Status.PreviousSKID = ""
			pkir.Status.RotationStartedAt = nil
			return r.transitionTo(ctx, pkir, platformv1alpha1.PhaseIdle, "SameKeyRenewal")
		}
		// Active CertificateRequest — renewal still in progress.
		return ctrl.Result{RequeueAfter: 10 * time.Second}, nil
	}
	pkir.Status.CurrentSKID = skid
	return r.transitionTo(ctx, pkir, platformv1alpha1.PhaseDualTrustActive, "RootCARenewed")
}

// reconcileDualTrustActive appends the new root PEM to the staging ConfigMap
// (creating the dual-trust window) and triggers re-issuance of only the
// cluster-level (tier-1) intermediate CAs. Tier-2 and leaf certs are triggered
// later in AwaitingReissuance, after tier-1 is confirmed, to avoid the race
// condition where tier-2 is signed by the old tier-1 key. Advances to
// AwaitingReissuance.
func (r *PKIRotationReconciler) reconcileDualTrustActive(
	ctx context.Context, pkir *platformv1alpha1.PKIRotation,
) (ctrl.Result, error) {
	log := logf.FromContext(ctx)

	// 1. Append new root PEM to staging ConfigMap alongside old root.
	if err := r.extendStagingConfigMap(ctx, pkir); err != nil {
		r.setCondition(
			pkir, platformv1alpha1.ConditionDualTrustActive, metav1.ConditionFalse,
			platformv1alpha1.ReasonStagingWriteFailed, err.Error(),
		)
		r.updateConditionStatus(ctx, pkir, "staging ConfigMap write failed")
		return ctrl.Result{}, fmt.Errorf("extending staging ConfigMap: %w", err)
	}
	r.setCondition(
		pkir, platformv1alpha1.ConditionDualTrustActive, metav1.ConditionTrue, "StagingConfigMapExtended",
		"Both old and new root PEMs present in staging ConfigMap",
	)

	// 2. Discover tier-1 intermediates (issued directly by the root ClusterIssuer)
	// and trigger re-issuance.
	tier1, err := r.discoverIntermediates(ctx, pkir)
	if err != nil {
		return ctrl.Result{}, fmt.Errorf("discovering tier-1 intermediates: %w", err)
	}
	log.Info("discovered tier-1 intermediates for re-issuance", "count", len(tier1))

	for i := range tier1 {
		if err := r.triggerReissuance(ctx, &tier1[i]); err != nil {
			return ctrl.Result{}, fmt.Errorf(
				"triggering reissuance for %s/%s: %w", tier1[i].Namespace, tier1[i].Name, err,
			)
		}
		log.Info("triggered re-issuance", "certificate", fmt.Sprintf("%s/%s", tier1[i].Namespace, tier1[i].Name))
	}

	// Tier-2 intermediates and leaf certs are NOT triggered here. They will be
	// triggered in AwaitingReissuance only after tier-1 AKID is confirmed against
	// the new root SKID. This sequential ordering prevents cert-manager from
	// signing tier-2 certs with the old tier-1 key before tier-1's Secret is
	// updated.
	r.setCondition(
		pkir,
		platformv1alpha1.ConditionIntermediateReissued,
		metav1.ConditionFalse,
		platformv1alpha1.ReasonAnnotationApplied,
		fmt.Sprintf(
			"Re-issuance triggered for %d cluster intermediate(s); tier-2 and leaf certs triggered after tier-1 confirmed",
			len(tier1),
		),
	)
	r.Recorder.Eventf(
		pkir, corev1.EventTypeNormal, "ReissuanceTriggered",
		"Triggered re-issuance of %d cluster intermediate CA(s); tier-2 will be triggered after tier-1 is confirmed",
		len(tier1),
	)

	return r.transitionTo(ctx, pkir, platformv1alpha1.PhaseAwaitingReissuance, "ReissuanceTriggered")
}

// reconcileAwaitingReissuance drives sequential cascade re-issuance:
//
//  1. Wait for tier-1 (cluster intermediate) AKID == new root SKID.
//  2. Trigger tier-2 (namespace intermediates) only after tier-1 is confirmed.
//     Sequential ordering is critical: triggering tier-2 before tier-1's Secret
//     is written causes cert-manager to sign tier-2 with the old tier-1 key.
//  3. Wait for all tier-2 certs NotBefore > tier-1 NotBefore.
//  4. Trigger leaf certs after tier-2 is confirmed.
//  5. Advance to VerifyingChain.
//
// Emits a Warning event if the reissuance timeout is exceeded but continues
// waiting — no autonomous abort.
func (r *PKIRotationReconciler) reconcileAwaitingReissuance(
	ctx context.Context, pkir *platformv1alpha1.PKIRotation,
) (ctrl.Result, error) {
	tier1, err := r.discoverIntermediates(ctx, pkir)
	if err != nil {
		return ctrl.Result{}, fmt.Errorf("discovering tier-1 intermediates: %w", err)
	}

	reissued, err := r.tier1ReissuedAgainstNewRoot(ctx, pkir, tier1)
	if err != nil {
		return ctrl.Result{}, err
	}
	if !reissued {
		return r.waitForReissuance(ctx, pkir, "Waiting for cluster intermediate CA re-issuance")
	}

	// Tier-1 done. The latest NotBefore across tier-1 is the baseline every
	// tier-2 certificate must post-date to count as re-issued.
	clusterIntNotBefore := latestNotBefore(tier1)

	tier2, err := r.discoverNamespaceIntermediates(ctx, tier1)
	if err != nil {
		return ctrl.Result{}, fmt.Errorf("discovering tier-2 intermediates: %w", err)
	}

	if err := r.triggerStaleTier2(ctx, tier2, clusterIntNotBefore); err != nil {
		return ctrl.Result{}, err
	}
	if msg := r.tier2PendingReason(ctx, tier2, clusterIntNotBefore); msg != "" {
		return r.waitForReissuance(ctx, pkir, msg)
	}

	leafCount, err := r.triggerLeafReissuance(ctx, pkir, tier1, tier2)
	if err != nil {
		return ctrl.Result{}, err
	}

	r.setCondition(pkir, platformv1alpha1.ConditionIntermediateReissued, metav1.ConditionTrue,
		"AllIntermediatesReissued",
		fmt.Sprintf("All intermediate CAs renewed (%d cluster, %d namespace); triggered %d leaf cert(s)",
			len(tier1), len(tier2), leafCount))
	return r.transitionTo(ctx, pkir, platformv1alpha1.PhaseVerifyingChain, "IntermediatesReissued")
}

// tier1ReissuedAgainstNewRoot reports whether every cluster intermediate now
// carries an AKID equal to the new root SKID, which is the only proof that
// cert-manager signed it with the new root rather than the outgoing one.
func (r *PKIRotationReconciler) tier1ReissuedAgainstNewRoot(
	ctx context.Context, pkir *platformv1alpha1.PKIRotation, tier1 []cmv1.Certificate,
) (bool, error) {
	log := logf.FromContext(ctx)
	for _, cert := range tier1 {
		akid, err := r.certificateAKID(ctx, &cert)
		if err != nil {
			return false, fmt.Errorf("reading AKID for %s/%s: %w", cert.Namespace, cert.Name, err)
		}
		if akid == "" || akid != pkir.Status.CurrentSKID {
			log.Info("tier-1 intermediate not yet reissued",
				"certificate", fmt.Sprintf("%s/%s", cert.Namespace, cert.Name), "akid", akid)
			return false, nil
		}
	}
	return true, nil
}

// triggerStaleTier2 re-issues every namespace intermediate still older than the
// new tier-1. Triggering only after tier-1 is confirmed is what makes
// cert-manager sign tier-2 with the new tier-1 Secret rather than the old one.
// The trigger is idempotent: Issuing=True is a no-op on a certificate already
// being renewed.
func (r *PKIRotationReconciler) triggerStaleTier2(
	ctx context.Context, tier2 []cmv1.Certificate, clusterIntNotBefore time.Time,
) error {
	log := logf.FromContext(ctx)
	for i := range tier2 {
		if tier2[i].Status.NotBefore != nil && tier2[i].Status.NotBefore.After(clusterIntNotBefore) {
			continue
		}
		if err := r.triggerReissuance(ctx, &tier2[i]); err != nil {
			return fmt.Errorf("triggering reissuance for tier-2 %s/%s: %w",
				tier2[i].Namespace, tier2[i].Name, err)
		}
		log.Info("triggered tier-2 re-issuance after tier-1 confirmed",
			"certificate", fmt.Sprintf("%s/%s", tier2[i].Namespace, tier2[i].Name))
	}
	return nil
}

// tier2PendingReason returns the wait message for the first namespace
// intermediate that is not yet re-issued against the new tier-1, or "" when
// every one of them is.
func (r *PKIRotationReconciler) tier2PendingReason(
	ctx context.Context, tier2 []cmv1.Certificate, clusterIntNotBefore time.Time,
) string {
	log := logf.FromContext(ctx)
	for _, cert := range tier2 {
		if !isCertificateResourceReady(&cert) {
			log.Info("tier-2 intermediate re-issuance in progress",
				"certificate", fmt.Sprintf("%s/%s", cert.Namespace, cert.Name))
			return "Namespace intermediate CA re-issuance in progress"
		}
		if cert.Status.NotBefore == nil || !cert.Status.NotBefore.After(clusterIntNotBefore) {
			log.Info("tier-2 intermediate not yet reissued",
				"certificate", fmt.Sprintf("%s/%s", cert.Namespace, cert.Name))
			return "Waiting for namespace intermediate CA re-issuance"
		}
	}
	return ""
}

// triggerLeafReissuance re-issues every leaf below the rotated intermediates and
// returns how many were triggered. cert-manager does not cascade from an
// intermediate key change to its leaves, so each one is triggered explicitly,
// and only once the intermediates are confirmed fresh so the leaves are signed
// with the new intermediate keys. Triggering is idempotent.
func (r *PKIRotationReconciler) triggerLeafReissuance(
	ctx context.Context, pkir *platformv1alpha1.PKIRotation, tier1, tier2 []cmv1.Certificate,
) (int, error) {
	log := logf.FromContext(ctx)
	leaves, err := r.discoverLeafCerts(ctx, tier1, tier2)
	if err != nil {
		return 0, fmt.Errorf("discovering leaf certs: %w", err)
	}
	log.Info("discovered leaf certs for re-issuance", "count", len(leaves))
	for i := range leaves {
		if err := r.triggerReissuance(ctx, &leaves[i]); err != nil {
			return 0, fmt.Errorf("triggering reissuance for leaf %s/%s: %w",
				leaves[i].Namespace, leaves[i].Name, err)
		}
		log.Info("triggered leaf re-issuance",
			"certificate", fmt.Sprintf("%s/%s", leaves[i].Namespace, leaves[i].Name))
	}
	if len(leaves) > 0 {
		r.Recorder.Eventf(pkir, corev1.EventTypeNormal, "LeafReissuanceTriggered",
			"Triggered re-issuance of %d leaf cert(s) after intermediate CA rotation", len(leaves))
	}
	return len(leaves), nil
}

// waitForReissuance updates the IntermediateReissued condition, emits a timeout
// warning if needed, and returns a requeue result.
func (r *PKIRotationReconciler) waitForReissuance(
	ctx context.Context, pkir *platformv1alpha1.PKIRotation, msg string,
) (ctrl.Result, error) {
	timeout := pkir.Spec.ReissuanceTimeout.Duration
	if timeout == 0 {
		timeout = defaultReissuanceTimeout
	}
	if pkir.Status.RotationStartedAt != nil && time.Since(pkir.Status.RotationStartedAt.Time) > timeout {
		r.Recorder.Eventf(pkir, corev1.EventTypeWarning, "ReissuanceTimeout",
			"Intermediate CA re-issuance has not completed after %s; check cert-manager status", timeout)
		recordReissuanceTimeout(pkir)
	}
	r.setCondition(
		pkir, platformv1alpha1.ConditionIntermediateReissued, metav1.ConditionFalse,
		platformv1alpha1.ReasonAwaitingCertMgrRenewal, msg,
	)
	r.updateConditionStatus(ctx, pkir, "awaiting cert-manager renewal")
	return ctrl.Result{RequeueAfter: 30 * time.Second}, nil
}

// reconcileVerifyingChain performs a final three-tier check before removing the old
// root from the trust bundle.
//
// Tier-1: cluster intermediate AKID must match the new root SKID (Secret read).
// Tier-2: namespace intermediates must have status.NotBefore after the cluster
// intermediate rotation, confirming the full cascade is complete.
// Tier-3: leaf certs must have status.NotBefore after the latest intermediate
// rotation, confirming they chain to the new intermediate keys. The old root
// is not removed until all leaf certs are fresh — otherwise clients with the
// new-root-only trust bundle would reject servers presenting old leaf chains.
func (r *PKIRotationReconciler) reconcileVerifyingChain(
	ctx context.Context, pkir *platformv1alpha1.PKIRotation,
) (ctrl.Result, error) {
	tier1, err := r.discoverIntermediates(ctx, pkir)
	if err != nil {
		return ctrl.Result{}, fmt.Errorf("discovering tier-1 intermediates: %w", err)
	}
	if res, err := r.verifyTier1Chain(ctx, pkir, tier1); res != nil || err != nil {
		return derefResult(res), err
	}

	clusterIntNotBefore := latestNotBefore(tier1)
	tier2, err := r.discoverNamespaceIntermediates(ctx, tier1)
	if err != nil {
		return ctrl.Result{}, fmt.Errorf("discovering tier-2 intermediates: %w", err)
	}
	if res := r.verifyTier2Chain(ctx, pkir, tier2, clusterIntNotBefore); res != nil {
		return *res, nil
	}

	leaves, err := r.discoverLeafCerts(ctx, tier1, tier2)
	if err != nil {
		return ctrl.Result{}, fmt.Errorf("discovering leaf certs: %w", err)
	}
	if res := r.verifyLeafChain(ctx, pkir, leaves, tier2, clusterIntNotBefore); res != nil {
		return *res, nil
	}

	// Counted at verified completion for the same reason as the IntermediateCA
	// path (issue #268): the trigger site can be observed more than once, this
	// block runs once per rotation, and the verified counts are the honest ones.
	recordDownstreamReissued(pkir, len(tier1)+len(tier2), len(leaves))
	r.setCondition(pkir, platformv1alpha1.ConditionChainVerified, metav1.ConditionTrue,
		platformv1alpha1.ReasonVerified,
		fmt.Sprintf("Full chain verified: %d cluster + %d namespace intermediates, %d leaf certs",
			len(tier1), len(tier2), len(leaves)))
	r.Recorder.Event(pkir, corev1.EventTypeNormal, "ChainVerified",
		"PKI chain verified; removing old root from trust bundle")
	return r.transitionTo(ctx, pkir, platformv1alpha1.PhaseComplete, "ChainVerified")
}

// reconcileComplete removes the old root PEM from the staging ConfigMap,
// cleans up the renewBefore trigger annotation on intermediate CAs,
// clears rotation state, and returns to Idle.
func (r *PKIRotationReconciler) reconcileComplete(
	ctx context.Context, pkir *platformv1alpha1.PKIRotation,
) (ctrl.Result, error) {
	if err := r.trimStagingConfigMap(ctx, pkir); err != nil {
		return ctrl.Result{}, fmt.Errorf("trimming staging ConfigMap: %w", err)
	}
	if err := r.clearReissuanceTrigger(ctx, pkir); err != nil {
		return ctrl.Result{}, fmt.Errorf("clearing renewBefore trigger annotations: %w", err)
	}

	pkir.Status.PreviousSKID = ""
	pkir.Status.RotationStartedAt = nil
	pkir.Status.DualTrustActiveAt = nil
	if err := r.syncChildSKIDs(ctx, pkir); err != nil {
		return ctrl.Result{}, fmt.Errorf("syncing child intermediate CA SKIDs: %w", err)
	}
	r.Recorder.Event(
		pkir, corev1.EventTypeNormal, "RotationComplete",
		"Root CA rotation complete; trust bundle updated to new root only",
	)
	return r.transitionTo(ctx, pkir, platformv1alpha1.PhaseIdle, "RotationComplete")
}
