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

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	ctrl "sigs.k8s.io/controller-runtime"
	logf "sigs.k8s.io/controller-runtime/pkg/log"

	platformv1alpha1 "github.com/adaptive-enforcement-lab/private-pki-operator/ci/private-pki-operator/api/v1alpha1"
)

// Phase and condition writes. Every status mutation on a PKIRotation goes
// through here so the phase, its condition and its event stay in step.

// --- Helpers -----------------------------------------------------------------

// transitionTo updates status.phase and records the transition time.
func (r *PKIRotationReconciler) transitionTo(
	ctx context.Context, pkir *platformv1alpha1.PKIRotation, phase platformv1alpha1.PKIRotationPhase, reason string,
) (ctrl.Result, error) {
	now := metav1.Now()
	// Captured before the overwrite: the counter needs the phase being left, and
	// transitionTo is the only place that still knows it.
	from := pkir.Status.Phase
	pkir.Status.Phase = phase
	pkir.Status.LastTransitionTime = &now
	if phase == platformv1alpha1.PhasePreservingOldRoot && pkir.Status.RotationStartedAt == nil {
		pkir.Status.RotationStartedAt = &now
	}
	// Also set RotationStartedAt when an IntermediateCA CR enters AwaitingReissuance.
	if phase == platformv1alpha1.PhaseAwaitingReissuance &&
		pkir.Spec.Role == platformv1alpha1.RoleIntermediateCA &&
		pkir.Status.RotationStartedAt == nil {
		pkir.Status.RotationStartedAt = &now
	}
	if phase == platformv1alpha1.PhaseDualTrustActive {
		pkir.Status.DualTrustActiveAt = &now
	}
	logf.FromContext(ctx).Info("phase transition", "phase", phase, "reason", reason)
	if err := r.Status().Update(ctx, pkir); err != nil {
		return ctrl.Result{}, err
	}
	// Recorded only after the write lands. Counting an intent that failed to
	// persist would report rotations the cluster never saw.
	recordTransition(pkir, from, phase)
	recordPhase(pkir)
	return ctrl.Result{}, nil
}

// updateConditionStatus persists a condition-only status update, logging rather
// than propagating a failure.
//
// Every caller has already decided what happens next — either it is returning an
// error, or it is requeuing to try again — and a failed diagnostic write should
// change neither. Propagating would abort a rotation that is otherwise
// progressing, on the strength of a write whose only job was to explain the
// progress.
//
// What it must not do is what it did before: discard the error silently. A
// status write that keeps failing — a conflict loop, a lost RBAC grant — then
// leaves the CR with no condition and nothing anywhere saying why. That is the
// same shape as issue #259, where a phase that was never written went unnoticed
// for four weeks because nothing reported the absence.
func (r *PKIRotationReconciler) updateConditionStatus(
	ctx context.Context, pkir *platformv1alpha1.PKIRotation, reason string,
) {
	if err := r.Status().Update(ctx, pkir); err != nil {
		logf.FromContext(ctx).
			Error(err, "failed to persist condition update; the CR will not show why this rotation is where it is",
				"reason", reason, "phase", pkir.Status.Phase)
	}
}

// setCondition upserts a condition on the PKIRotation status.
func (r *PKIRotationReconciler) setCondition(
	pkir *platformv1alpha1.PKIRotation, condType string, status metav1.ConditionStatus, reason, message string,
) {
	now := metav1.Now()
	for i, c := range pkir.Status.Conditions {
		if c.Type == condType {
			pkir.Status.Conditions[i].Status = status
			pkir.Status.Conditions[i].Reason = reason
			pkir.Status.Conditions[i].Message = message
			pkir.Status.Conditions[i].LastTransitionTime = now
			return
		}
	}
	pkir.Status.Conditions = append(pkir.Status.Conditions, metav1.Condition{
		Type:               condType,
		Status:             status,
		Reason:             reason,
		Message:            message,
		LastTransitionTime: now,
	})
}
