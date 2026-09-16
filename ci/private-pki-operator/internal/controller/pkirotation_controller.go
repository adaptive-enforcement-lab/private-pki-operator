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
	"time"

	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/client-go/tools/record"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	logf "sigs.k8s.io/controller-runtime/pkg/log"

	platformv1alpha1 "github.com/adaptive-enforcement-lab/private-pki-operator/ci/private-pki-operator/api/v1alpha1"
)

// PKIRotationReconciler drives the dual-trust root CA rotation state machine.
// The phase handlers live in pkirotation_phases.go; this file holds the type,
// its shared configuration and the dispatch loop.

const (
	defaultReissuanceTimeout = 15 * time.Minute
	issuerKindClusterIssuer  = "ClusterIssuer"
	// trustBundleKey is the ConfigMap and Bundle data key carrying the trust
	// anchors. It is the cert-manager convention and is fixed by whatever mounts
	// the bundle, so it is named once here rather than repeated per call site.
	trustBundleKey = "ca.crt"
)

// PKIRotationReconciler reconciles PKIRotation objects.
type PKIRotationReconciler struct {
	client.Client
	// Reader is an uncached client used for Secret reads outside the cert-manager
	// namespace (intermediate CA Secrets in chaos-mesh, security, rabbitmq, etc.).
	// Set to mgr.GetAPIReader() so reads bypass the cache-namespace restriction
	// without requiring cluster-wide Secret caching. Nil in tests (falls back to Client).
	Reader   client.Reader
	Scheme   *runtime.Scheme
	Recorder record.EventRecorder
}

// getReader returns the uncached reader if configured, otherwise falls back to
// the cached client. Tests omit Reader; production always sets it to GetAPIReader().
func (r *PKIRotationReconciler) getReader() client.Reader {
	if r.Reader != nil {
		return r.Reader
	}
	return r.Client
}

//
//nolint:lll // the kubebuilder RBAC marker must stay on one line
// +kubebuilder:rbac:groups=platform.adaptive-enforcement-lab.com,resources=pkirotations,verbs=get;list;watch;create;update;patch;delete
// +kubebuilder:rbac:groups=platform.adaptive-enforcement-lab.com,resources=pkirotations/status,verbs=get;update;patch
// +kubebuilder:rbac:groups=platform.adaptive-enforcement-lab.com,resources=pkirotations/finalizers,verbs=update

// Namespace-scoped permissions (Role in cert-manager — see charts/.../role.yaml).
// Reissuance is triggered via certificates/status patch (Issuing=True condition),
// the same mechanism used by cmctl renew. No write access to Secrets is required.
// +kubebuilder:rbac:groups=cert-manager.io,resources=certificaterequests,verbs=get;list;watch
// +kubebuilder:rbac:groups="",resources=secrets,verbs=get;list;watch
// +kubebuilder:rbac:groups="",resources=configmaps,verbs=get;list;watch;create;patch

// Cluster-scoped permissions (ClusterRole — see charts/.../clusterrole.yaml).
// Certificates are watched and patched cluster-wide so the operator can discover
// and trigger re-issuance of namespace-scoped intermediate CAs during rotation.
// Events are cluster-scoped: PKIRotation is a cluster-scoped CRD and
// controller-runtime emits Events to the default namespace, not the operator namespace.
// +kubebuilder:rbac:groups="",resources=events,verbs=create;patch
// +kubebuilder:rbac:groups=cert-manager.io,resources=clusterissuers,verbs=get;list;watch
// +kubebuilder:rbac:groups=cert-manager.io,resources=certificates,verbs=get;list;watch;patch
// +kubebuilder:rbac:groups=cert-manager.io,resources=certificates/status,verbs=patch
// +kubebuilder:rbac:groups=trust.cert-manager.io,resources=bundles,verbs=get;list;watch;create;patch

// Reconcile drives the PKIRotation state machine forward.
// It is edge-triggered (by the four watches below) and level-driven:
// it reads the current phase from status and advances to the next correct state.
// Every step is idempotent — re-entering a state from a restart is safe.
func (r *PKIRotationReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	log := logf.FromContext(ctx)

	var pkir platformv1alpha1.PKIRotation
	if err := r.Get(ctx, req.NamespacedName, &pkir); err != nil {
		if apierrors.IsNotFound(err) {
			// Drop the object's series; a gauge left behind reads as a rotation
			// permanently stuck in whatever phase it held when it was deleted.
			forgetPhase(req.Name)
		}
		return ctrl.Result{}, client.IgnoreNotFound(err)
	}

	// Export the phase on every observation, not only on transition. A CR that
	// never transitions still has a phase worth reporting — including the empty
	// one, which is the fault in issue #259 and would otherwise be invisible
	// precisely because nothing ever happens to it.
	recordPhase(&pkir)

	// Route IntermediateCA CRs to the cascade-only state machine.
	// Empty role (omitempty default) is treated as RootCA and falls through below.
	if pkir.Spec.Role == platformv1alpha1.RoleIntermediateCA {
		return r.reconcileIntermediate(ctx, &pkir)
	}
	// RoleRootCA (or empty/default) falls through to the full rotation state machine below.

	// Initialise phase to Idle on first reconcile.
	if pkir.Status.Phase == "" {
		return r.transitionTo(ctx, &pkir, platformv1alpha1.PhaseIdle, "Initialised")
	}

	switch pkir.Status.Phase {
	case platformv1alpha1.PhaseIdle:
		return r.reconcileIdle(ctx, &pkir)
	case platformv1alpha1.PhasePreservingOldRoot:
		return r.reconcilePreservingOldRoot(ctx, &pkir)
	case platformv1alpha1.PhaseDualTrustActive:
		return r.reconcileDualTrustActive(ctx, &pkir)
	case platformv1alpha1.PhaseAwaitingReissuance:
		return r.reconcileAwaitingReissuance(ctx, &pkir)
	case platformv1alpha1.PhaseVerifyingChain:
		return r.reconcileVerifyingChain(ctx, &pkir)
	case platformv1alpha1.PhaseComplete:
		return r.reconcileComplete(ctx, &pkir)
	}

	log.Info("unknown phase, resetting to Idle", "phase", pkir.Status.Phase)
	return r.transitionTo(ctx, &pkir, platformv1alpha1.PhaseIdle, "UnknownPhaseReset")
}
