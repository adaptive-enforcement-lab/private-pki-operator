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
	"strings"
	"time"

	cmv1 "github.com/cert-manager/cert-manager/pkg/apis/certmanager/v1"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	logf "sigs.k8s.io/controller-runtime/pkg/log"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"

	platformv1alpha1 "github.com/adaptive-enforcement-lab/private-pki-operator/ci/private-pki-operator/api/v1alpha1"
	"github.com/adaptive-enforcement-lab/private-pki-operator/ci/private-pki-operator/internal/pki"
)

// reconcileIntermediate is the entry point for IntermediateCA-role PKIRotations.
// It dispatches to the cascade-only state machine based on phase.
func (r *PKIRotationReconciler) reconcileIntermediate(
	ctx context.Context, pkir *platformv1alpha1.PKIRotation,
) (ctrl.Result, error) {
	log := logf.FromContext(ctx)

	switch pkir.Status.Phase {
	case "", platformv1alpha1.PhaseIdle:
		return r.reconcileIdleIntermediate(ctx, pkir)
	case platformv1alpha1.PhaseAwaitingReissuance:
		return r.reconcileAwaitingReissuanceIntermediate(ctx, pkir)
	case platformv1alpha1.PhaseVerifyingChain:
		return r.reconcileVerifyingChainIntermediate(ctx, pkir)
	case platformv1alpha1.PhaseComplete:
		return r.reconcileCompleteIntermediate(ctx, pkir)
	default:
		// Phases not valid for IntermediateCA (PreservingOldRoot, DualTrustActive)
		// should never be reached. Log and return to Idle.
		log.Info("IntermediateCA PKIRotation in unexpected phase, resetting to Idle", "phase", pkir.Status.Phase)
		return r.transitionTo(ctx, pkir, platformv1alpha1.PhaseIdle, "UnexpectedPhase")
	}
}

// reconcileIdleIntermediate handles the Idle phase for role=IntermediateCA PKIRotation CRs.
//
// Four outcomes:
//  1. spec.intermediateCA == nil → return error (misconfiguration)
//  2. status.currentSKID == "" (first run) → read SKID from Secret, store in status, return (no cascade)
//  3. SKID unchanged → no-op, return
//  4. SKID changed:
//     - Check owner: call isOwnerRootCAIdle(ctx, pkir)
//     - If owner NOT Idle: yield — update status.currentSKID = newSKID, requeue 30s, stay Idle
//     - If owner IS Idle (or no owner): transition to AwaitingReissuance
func (r *PKIRotationReconciler) reconcileIdleIntermediate(
	ctx context.Context, pkir *platformv1alpha1.PKIRotation,
) (ctrl.Result, error) {
	log := logf.FromContext(ctx)

	if pkir.Spec.IntermediateCA == nil {
		return ctrl.Result{}, fmt.Errorf("role=IntermediateCA but spec.intermediateCA is nil")
	}

	newSKID, err := r.intermediateSKID(ctx, pkir)
	if err != nil {
		return ctrl.Result{}, fmt.Errorf("reading intermediate CA SKID: %w", err)
	}

	// Outcome 2: first run — record baseline SKID and set phase to Idle.
	if pkir.Status.CurrentSKID == "" {
		log.Info("recording intermediate CA SKID (first run)", "skid", newSKID)
		pkir.Status.CurrentSKID = newSKID
		pkir.Status.Phase = platformv1alpha1.PhaseIdle
		if err := r.Status().Update(ctx, pkir); err != nil {
			return ctrl.Result{}, fmt.Errorf("updating status with intermediate CA SKID: %w", err)
		}
		return ctrl.Result{}, nil
	}

	// Outcome 3: SKID unchanged — no-op, except for one repair.
	//
	// The dispatcher routes an EMPTY phase here alongside Idle, and this early
	// return used to fire before anything wrote a phase. A CR that reached the
	// state "currentSKID populated, phase empty" therefore stayed there forever:
	// every later reconcile matched the SKID and returned here, and nothing else
	// ever ran. Two CRs sat like that in STG, PRD and OPS for four weeks, across
	// an operator restart and leader re-election (issue #259).
	//
	// Normalising the phase here closes it at the only point every such CR is
	// guaranteed to pass through.
	if pkir.Status.CurrentSKID == newSKID {
		if pkir.Status.Phase == "" {
			log.Info("normalising empty phase to Idle", "skid", newSKID)
			pkir.Status.Phase = platformv1alpha1.PhaseIdle
			if err := r.Status().Update(ctx, pkir); err != nil {
				return ctrl.Result{}, fmt.Errorf("normalising empty phase to Idle: %w", err)
			}
			recordPhase(pkir)
		}
		return ctrl.Result{}, nil
	}

	// Outcome 4: SKID changed — check owner before cascading.
	log.Info("intermediate CA SKID changed", "oldSKID", pkir.Status.CurrentSKID, "newSKID", newSKID)

	ownerIdle, err := r.isOwnerRootCAIdle(ctx, pkir)
	if err != nil {
		return ctrl.Result{}, fmt.Errorf("checking owner PKIRotation phase: %w", err)
	}

	// Update currentSKID in all SKID-changed paths.
	pkir.Status.CurrentSKID = newSKID

	if !ownerIdle {
		// Owner is still rotating — yield and check back later.
		//
		// The phase is set explicitly rather than left alone: this path writes
		// status while the CR may still hold an empty phase, and writing the SKID
		// without the phase is how a CR entered the stuck state in #259.
		log.Info("owner PKIRotation is not Idle; yielding intermediate cascade", "requeue", "30s")
		pkir.Status.Phase = platformv1alpha1.PhaseIdle
		if err := r.Status().Update(ctx, pkir); err != nil {
			return ctrl.Result{}, fmt.Errorf("updating status on yield: %w", err)
		}
		recordPhase(pkir)
		return ctrl.Result{RequeueAfter: 30 * time.Second}, nil
	}

	// Owner is Idle (or no owner) — cascade into AwaitingReissuance.
	return r.transitionTo(ctx, pkir, platformv1alpha1.PhaseAwaitingReissuance, "IntermediateSKIDChanged")
}

// reconcileCompleteIntermediate handles the Complete phase for role=IntermediateCA PKIRotation CRs.
// Clears previousSKID and rotationStartedAt, emits an event, and transitions to Idle.
func (r *PKIRotationReconciler) reconcileCompleteIntermediate(
	ctx context.Context, pkir *platformv1alpha1.PKIRotation,
) (ctrl.Result, error) {
	pkir.Status.PreviousSKID = ""
	pkir.Status.RotationStartedAt = nil
	r.Recorder.Event(
		pkir, corev1.EventTypeNormal, "IntermediateRotationComplete",
		"Intermediate CA cascade rotation complete; returning to Idle",
	)
	return r.transitionTo(ctx, pkir, platformv1alpha1.PhaseIdle, "IntermediateRotationComplete")
}

// intermediateSKID reads the intermediate CA Certificate identified by
// spec.intermediateCA, then reads its backing Secret, and extracts the SKID.
func (r *PKIRotationReconciler) intermediateSKID(
	ctx context.Context, pkir *platformv1alpha1.PKIRotation,
) (string, error) {
	ref := pkir.Spec.IntermediateCA

	var cert cmv1.Certificate
	if err := r.Get(ctx, types.NamespacedName{
		Name:      ref.CertificateName,
		Namespace: ref.CertificateNamespace,
	}, &cert); err != nil {
		return "", fmt.Errorf(
			"getting intermediate CA Certificate %s/%s: %w", ref.CertificateNamespace, ref.CertificateName, err,
		)
	}

	var secret corev1.Secret
	// Use uncached reader: intermediate CA Secrets can live in any namespace
	// (any workload namespace) outside the cache's cert-manager restriction.
	if err := r.getReader().Get(ctx, types.NamespacedName{
		Name:      cert.Spec.SecretName,
		Namespace: ref.CertificateNamespace,
	}, &secret); err != nil {
		return "", fmt.Errorf(
			"getting intermediate CA Secret %s/%s: %w", ref.CertificateNamespace, cert.Spec.SecretName, err,
		)
	}

	certPEM, ok := secret.Data["tls.crt"]
	if !ok {
		return "", fmt.Errorf(
			"intermediate CA Secret %s/%s missing tls.crt key", ref.CertificateNamespace, cert.Spec.SecretName,
		)
	}
	return pki.SKIDFromPEM(certPEM)
}

// isOwnerRootCAIdle iterates pkir.OwnerReferences, finds the first entry with
// Kind == "PKIRotation", fetches it, and returns true if its phase is Idle or "".
// If no PKIRotation owner is found, returns (true, nil) — no owner means proceed.
func (r *PKIRotationReconciler) isOwnerRootCAIdle(
	ctx context.Context, pkir *platformv1alpha1.PKIRotation,
) (bool, error) {
	for _, ref := range pkir.OwnerReferences {
		if ref.Kind != "PKIRotation" {
			continue
		}
		var owner platformv1alpha1.PKIRotation
		if err := r.Get(ctx, types.NamespacedName{Name: ref.Name}, &owner); err != nil {
			return false, fmt.Errorf("getting owner PKIRotation %s: %w", ref.Name, err)
		}
		return owner.Status.Phase == platformv1alpha1.PhaseIdle || owner.Status.Phase == "", nil
	}
	// No PKIRotation owner found — treat as Idle (no gating).
	return true, nil
}

// reconcileAwaitingReissuanceIntermediate drives downstream cascade re-issuance
// for a role=IntermediateCA PKIRotation.
//
// It resolves the intermediate CA Certificate, verifies the live Secret still
// carries the SKID recorded at transition time (guard against cert-manager
// rotating again mid-flight), then discovers and triggers re-issuance of all
// downstream CA and leaf certs. Once triggered it advances to VerifyingChain.
func (r *PKIRotationReconciler) reconcileAwaitingReissuanceIntermediate(
	ctx context.Context, pkir *platformv1alpha1.PKIRotation,
) (ctrl.Result, error) {
	intCert, err := r.loadIntermediateCert(ctx, pkir)
	if err != nil {
		return ctrl.Result{}, err
	}

	// Verify the intermediate CA Secret still contains the SKID we recorded.
	// If cert-manager has rotated again since reconcileIdleIntermediate ran,
	// we need to let reconcileIdleIntermediate re-detect the new SKID.
	liveIntSKID, err := r.intermediateSKID(ctx, pkir)
	if err != nil {
		return ctrl.Result{}, fmt.Errorf("reading intermediate CA SKID: %w", err)
	}
	if liveIntSKID != pkir.Status.CurrentSKID {
		// Cert-manager has rotated again mid-flight; reset to Idle so
		// reconcileIdleIntermediate sees the divergence (currentSKID != liveIntSKID)
		// and starts a fresh cascade for the new SKID.
		r.Recorder.Eventf(pkir, corev1.EventTypeWarning, "SKIDDriftDetected",
			"intermediate CA SKID changed from %s to %s during reissuance; resetting to Idle",
			pkir.Status.CurrentSKID, liveIntSKID)
		recordSKIDDrift(pkir)
		return r.transitionTo(ctx, pkir, platformv1alpha1.PhaseIdle, "SKIDDriftDetected")
	}

	// Discover all downstream certs (CA and leaf) below the intermediate CA.
	childAnchors, err := r.findIssuersForCACert(ctx, intCert)
	if err != nil {
		return ctrl.Result{}, fmt.Errorf(
			"finding issuers for intermediate CA %s/%s: %w", intCert.Namespace, intCert.Name, err,
		)
	}

	allCAs, allLeaves, err := r.discoverDownstreamBFS(ctx, childAnchors)
	if err != nil {
		return ctrl.Result{}, fmt.Errorf("discovering downstream certs: %w", err)
	}

	// Trigger re-issuance of all downstream certs.
	triggered, err := r.triggerDownstream(ctx, "CA", allCAs)
	if err != nil {
		return ctrl.Result{}, err
	}
	leavesTriggered, err := r.triggerDownstream(ctx, "leaf", allLeaves)
	if err != nil {
		return ctrl.Result{}, err
	}
	triggered += leavesTriggered

	r.setCondition(
		pkir,
		platformv1alpha1.ConditionIntermediateReissued,
		metav1.ConditionFalse,
		platformv1alpha1.ReasonAwaitingCertMgrRenewal,
		fmt.Sprintf(
			"Triggered re-issuance of %d downstream certs (%d CA, %d leaf); waiting for cert-manager renewal",
			triggered, len(allCAs), len(allLeaves),
		),
	)
	return r.transitionTo(ctx, pkir, platformv1alpha1.PhaseVerifyingChain, "DownstreamReissuanceTriggered")
}

// reconcileVerifyingChainIntermediate performs a final chain check for a
// role=IntermediateCA PKIRotation before advancing to Complete.
//
// All downstream CA and leaf certs must be Ready and have a NotBefore that is
// not before the intermediate CA's own NotBefore, confirming they were issued
// after the intermediate rotation.
func (r *PKIRotationReconciler) reconcileVerifyingChainIntermediate(
	ctx context.Context, pkir *platformv1alpha1.PKIRotation,
) (ctrl.Result, error) {
	intCert, err := r.loadIntermediateCert(ctx, pkir)
	if err != nil {
		return ctrl.Result{}, err
	}

	// Re-read the live intermediate SKID on every reconcile — idempotent operators
	// always derive decisions from live state, not from stored snapshots.  If
	// cert-manager has rotated the intermediate CA again while we were in
	// VerifyingChain (e.g. because a parallel cascade or manual deletion triggered
	// a second rotation), reset to Idle so reconcileIdleIntermediate picks up the
	// new SKID and starts a fresh downstream cascade.
	liveIntSKID, err := r.intermediateSKID(ctx, pkir)
	if err != nil {
		return ctrl.Result{}, fmt.Errorf("reading intermediate CA SKID: %w", err)
	}
	if liveIntSKID != pkir.Status.CurrentSKID {
		r.Recorder.Eventf(pkir, corev1.EventTypeWarning, "SKIDDriftDetected",
			"intermediate CA SKID changed from %s to %s during VerifyingChain; resetting to Idle",
			pkir.Status.CurrentSKID, liveIntSKID)
		recordSKIDDrift(pkir)
		return r.transitionTo(ctx, pkir, platformv1alpha1.PhaseIdle, "SKIDDriftDetected")
	}

	// The baseline: all downstream certs must have NotBefore >= intCert.Status.NotBefore.
	var intNotBefore time.Time
	if intCert.Status.NotBefore != nil {
		intNotBefore = intCert.Status.NotBefore.Time
	}

	// Discover all downstream certs.
	childAnchors, err := r.findIssuersForCACert(ctx, intCert)
	if err != nil {
		return ctrl.Result{}, fmt.Errorf("finding issuers for intermediate CA %s/%s: %w",
			intCert.Namespace, intCert.Name, err)
	}

	allCAs, allLeaves, err := r.discoverDownstreamBFS(ctx, childAnchors)
	if err != nil {
		return ctrl.Result{}, fmt.Errorf("discovering downstream certs: %w", err)
	}

	pending := r.pendingDownstreamCerts(ctx, pkir, childAnchors, allCAs, allLeaves, intNotBefore)
	if len(pending) > 0 {
		msg := fmt.Sprintf("pending: [%s]", strings.Join(pending, ", "))
		r.setCondition(pkir, platformv1alpha1.ConditionChainVerified, metav1.ConditionFalse,
			"LeafReissuancePending", msg)
		r.updateConditionStatus(ctx, pkir, "downstream chain not yet verified")
		return ctrl.Result{RequeueAfter: 15 * time.Second}, nil
	}

	r.markIntermediateChainVerified(pkir, allCAs, allLeaves)
	return r.transitionTo(ctx, pkir, platformv1alpha1.PhaseComplete, "IntermediateChainVerified")
}

// triggerDownstream re-issues every certificate in certs and returns how many
// were triggered. kind names the tier for the log line and the wrapped error —
// "CA" or "leaf" — so the two passes read distinctly in the operator log.
func (r *PKIRotationReconciler) triggerDownstream(
	ctx context.Context, kind string, certs []cmv1.Certificate,
) (int, error) {
	log := logf.FromContext(ctx)
	for i := range certs {
		if err := r.triggerReissuance(ctx, &certs[i]); err != nil {
			return 0, fmt.Errorf("triggering reissuance for %s %s/%s: %w",
				kind, certs[i].Namespace, certs[i].Name, err)
		}
		log.Info("triggered downstream "+kind+" re-issuance",
			"certificate", fmt.Sprintf("%s/%s", certs[i].Namespace, certs[i].Name))
	}
	return len(certs), nil
}

// loadIntermediateCert resolves the cert-manager Certificate that a
// role=IntermediateCA PKIRotation points at. A nil spec.intermediateCA is a
// malformed object, not a transient state, so it is returned as an error.
func (r *PKIRotationReconciler) loadIntermediateCert(
	ctx context.Context, pkir *platformv1alpha1.PKIRotation,
) (*cmv1.Certificate, error) {
	if pkir.Spec.IntermediateCA == nil {
		return nil, fmt.Errorf("role=IntermediateCA but spec.intermediateCA is nil")
	}
	ref := pkir.Spec.IntermediateCA
	var cert cmv1.Certificate
	key := types.NamespacedName{Name: ref.CertificateName, Namespace: ref.CertificateNamespace}
	if err := r.Get(ctx, key, &cert); err != nil {
		return nil, fmt.Errorf(
			"getting intermediate CA Certificate %s/%s: %w", ref.CertificateNamespace, ref.CertificateName, err,
		)
	}
	return &cert, nil
}

// markIntermediateChainVerified closes out both conditions and records the
// downstream counts on the transition to Complete.
//
// Both conditions are closed together. IntermediateReissued was set False with
// AwaitingCertManagerRenewal when the cascade was triggered, and nothing ever
// set it back — so every completed intermediate rotation in the estate
// permanently advertised an unfinished re-issuance, contradicting the
// ChainVerified=True sitting next to it (issue #260). The verification that
// justifies ChainVerified is the same evidence that the re-issuance landed:
// every downstream cert is Ready and was issued after the intermediate rotated.
// Closing one without the other is what made the pair inconsistent.
//
// The counts are recorded here rather than where the cascade was triggered. The
// trigger site runs once per reconcile of AwaitingReissuance and that phase can
// be observed more than once, so counting there measured trigger attempts: a
// live rotation over 3 leaves reported 6 (issue #268). This runs exactly once
// per rotation, and its counts are the verified ones — every cert Ready and
// issued after the intermediate rotated. That is also the more honest number:
// what was reissued, not what was asked for.
func (r *PKIRotationReconciler) markIntermediateChainVerified(
	pkir *platformv1alpha1.PKIRotation, allCAs, allLeaves []cmv1.Certificate,
) {
	recordDownstreamReissued(pkir, len(allCAs), len(allLeaves))
	r.setCondition(pkir, platformv1alpha1.ConditionIntermediateReissued, metav1.ConditionTrue,
		platformv1alpha1.ReasonAllDownstreamReissued,
		fmt.Sprintf("All %d downstream cert(s) reissued after intermediate CA rotation (%d CA, %d leaf)",
			len(allCAs)+len(allLeaves), len(allCAs), len(allLeaves)))
	r.setCondition(pkir, platformv1alpha1.ConditionChainVerified, metav1.ConditionTrue,
		platformv1alpha1.ReasonVerified,
		fmt.Sprintf("Full downstream chain verified: %d CA + %d leaf certs all reissued after intermediate CA rotation",
			len(allCAs), len(allLeaves)))
	r.Recorder.Event(pkir, corev1.EventTypeNormal, "IntermediateChainVerified",
		"Intermediate CA downstream chain verified; advancing to Complete")
}

// pendingDownstreamCerts names every downstream certificate that has not yet
// caught up with the rotated intermediate, re-triggering the ones cert-manager
// will not reissue on its own. An empty result is the proof that justifies
// ChainVerified=True.
//
// Three things make a certificate pending: it is not Ready; it predates the
// intermediate's NotBefore; or — for DIRECT children only — the AKID in its
// backing Secret does not match the intermediate's current SKID. The AKID check
// is scoped to direct children because indirect descendants chain to their own
// parent CA, so their AKID correctly differs and applying the check to them
// would produce permanent false negatives.
func (r *PKIRotationReconciler) pendingDownstreamCerts(
	ctx context.Context, pkir *platformv1alpha1.PKIRotation, childAnchors []issuerAnchor,
	allCAs, allLeaves []cmv1.Certificate, intNotBefore time.Time,
) []string {
	log := logf.FromContext(ctx)

	directAnchorNames := make(map[string]struct{}, len(childAnchors))
	for _, a := range childAnchors {
		directAnchorNames[a.Name] = struct{}{}
	}

	// Safe concatenation — no append aliasing.
	allDownstream := make([]cmv1.Certificate, 0, len(allCAs)+len(allLeaves))
	allDownstream = append(allDownstream, allCAs...)
	allDownstream = append(allDownstream, allLeaves...)

	var pending []string
	for _, cert := range allDownstream {
		if !isCertificateResourceReady(&cert) {
			log.Info("downstream cert re-issuance in progress",
				"certificate", fmt.Sprintf("%s/%s", cert.Namespace, cert.Name))
			pending = append(pending, fmt.Sprintf("%s/%s", cert.Namespace, cert.Name))
			continue
		}
		if cert.Status.NotBefore == nil || cert.Status.NotBefore.Time.Before(intNotBefore) {
			if !isCertificateIssuingTrue(&cert) {
				log.Info("downstream cert not yet reissued after intermediate CA rotation — re-triggering",
					"certificate", fmt.Sprintf("%s/%s", cert.Namespace, cert.Name))
				_ = r.triggerReissuance(ctx, &cert)
			}
			pending = append(pending, fmt.Sprintf("%s/%s", cert.Namespace, cert.Name))
			continue
		}
		if _, isDirect := directAnchorNames[cert.Spec.IssuerRef.Name]; !isDirect {
			continue
		}
		if r.directChildAKIDMismatched(ctx, pkir, &cert) {
			pending = append(pending, fmt.Sprintf("%s/%s (AKID mismatch)", cert.Namespace, cert.Name))
		}
	}
	return pending
}

// directChildAKIDMismatched reports whether a direct child was reissued
// (NotBefore is current) but signed by the OLD issuer key, which happens when
// cert-manager's Issuer cache still held the previous CA. cert-manager will not
// correct this on its own, so a mismatch re-triggers reissuance against the
// now-refreshed Issuer.
func (r *PKIRotationReconciler) directChildAKIDMismatched(
	ctx context.Context, pkir *platformv1alpha1.PKIRotation, cert *cmv1.Certificate,
) bool {
	log := logf.FromContext(ctx)
	leafAKID, err := r.certificateAKID(ctx, cert)
	if err != nil || leafAKID == "" || leafAKID == pkir.Status.CurrentSKID {
		return false
	}
	if isCertificateIssuingTrue(cert) {
		log.Info("downstream cert AKID mismatch — reissuance already in flight",
			"certificate", fmt.Sprintf("%s/%s", cert.Namespace, cert.Name),
			"akid", leafAKID, "intermediateSkid", pkir.Status.CurrentSKID)
		return true
	}
	log.Info("downstream cert AKID mismatch after reissuance — re-triggering",
		"certificate", fmt.Sprintf("%s/%s", cert.Namespace, cert.Name),
		"akid", leafAKID, "intermediateSkid", pkir.Status.CurrentSKID)
	_ = r.triggerReissuance(ctx, cert)
	return true
}

// intermediateSecretMapper maps a Secret change event to the IntermediateCA PKIRotation
// that owns it (if any). Called by the controller-runtime watch machinery whenever an
// intermediate CA Secret is created or updated. This is what makes the operator react
// when cert-manager rotates an intermediate CA's private key.
func (r *PKIRotationReconciler) intermediateSecretMapper(ctx context.Context, obj client.Object) []reconcile.Request {
	secret, ok := obj.(*corev1.Secret)
	if !ok {
		return nil
	}

	var all platformv1alpha1.PKIRotationList
	if err := r.List(ctx, &all); err != nil {
		logf.FromContext(ctx).Error(err, "intermediateSecretMapper: listing PKIRotations failed; Secret event dropped")
		return nil
	}

	var requests []reconcile.Request
	for _, pkir := range all.Items {
		if pkir.Spec.Role != platformv1alpha1.RoleIntermediateCA {
			continue
		}
		if pkir.Spec.IntermediateCA == nil {
			continue
		}

		// Get the Certificate to find its SecretName.
		var cert cmv1.Certificate
		if err := r.Get(ctx, types.NamespacedName{
			Name:      pkir.Spec.IntermediateCA.CertificateName,
			Namespace: pkir.Spec.IntermediateCA.CertificateNamespace,
		}, &cert); err != nil {
			if !apierrors.IsNotFound(err) {
				logf.FromContext(ctx).
					Error(err, "intermediateSecretMapper: failed to get Certificate; Secret event may be dropped",
						"pkirotation", pkir.Name,
						"certificate", pkir.Spec.IntermediateCA.CertificateName)
			}
			continue
		}

		if cert.Spec.SecretName == secret.Name && cert.Namespace == secret.Namespace {
			requests = append(requests, reconcile.Request{
				NamespacedName: types.NamespacedName{Name: pkir.Name},
			})
		}
	}
	return requests
}
