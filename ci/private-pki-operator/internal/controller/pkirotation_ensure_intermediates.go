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
	"crypto/sha256"
	"fmt"

	cmv1 "github.com/cert-manager/cert-manager/pkg/apis/certmanager/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller/controllerutil"
	logf "sigs.k8s.io/controller-runtime/pkg/log"

	platformv1alpha1 "github.com/adaptive-enforcement-lab/private-pki-operator/ci/private-pki-operator/api/v1alpha1"
)

const (
	// pkirotationAPIVersion is the hardcoded APIVersion for PKIRotation owner references.
	// The fetched object may have an empty APIVersion/Kind, so we hardcode it.
	pkirotationAPIVersion = "platform.adaptive-enforcement-lab.com/v1alpha1"
	// pkirotationKind is the hardcoded Kind for PKIRotation owner references.
	pkirotationKind = "PKIRotation"
	// maxPKIRNameLen is the maximum Kubernetes name length for cluster-scoped resources.
	maxPKIRNameLen = 63
	// hashSuffixLen is the number of hex characters from SHA-256 used as the name suffix.
	hashSuffixLen = 8
	// ownerPKIRLabel is applied to every child IntermediateCA PKIRotation CR to identify
	// its owning root PKIRotation by name. Used by syncChildSKIDs for efficient label-based
	// list filtering instead of a cluster-wide list + post-filter.
	ownerPKIRLabel = "platform.adaptive-enforcement-lab.com/owner-pkirotation"
)

// ensureIntermediateCACRs discovers all CA certs below the root CA's anchor and
// creates-or-updates a child PKIRotation CR (role=IntermediateCA) for each.
// This is called from reconcileIdle for RootCA PKIRotations.
// Child CRs carry an owner reference to the root PKIRotation for GC.
func (r *PKIRotationReconciler) ensureIntermediateCACRs(
	ctx context.Context, rootPKIR *platformv1alpha1.PKIRotation,
) error {
	// 1. Get the root CA Certificate.
	var rootCACert cmv1.Certificate
	if err := r.Get(ctx, types.NamespacedName{
		Name:      rootPKIR.Spec.RootCA.CertificateName,
		Namespace: rootPKIR.Spec.RootCA.CertificateNamespace,
	}, &rootCACert); err != nil {
		return fmt.Errorf("getting root CA Certificate %s/%s: %w",
			rootPKIR.Spec.RootCA.CertificateNamespace, rootPKIR.Spec.RootCA.CertificateName, err)
	}

	// 2. Find issuers anchored by the root CA cert.
	anchors, err := r.findIssuersForCACert(ctx, &rootCACert)
	if err != nil {
		return fmt.Errorf("finding issuers for root CA cert: %w", err)
	}

	// If no issuers found, there are no children to manage.
	if len(anchors) == 0 {
		return nil
	}

	// 3. Discover all downstream CA certs (ignore leaves).
	var allCAs []cmv1.Certificate
	for _, anchor := range anchors {
		cas, _, err := r.discoverDownstream(ctx, anchor)
		if err != nil {
			return fmt.Errorf("discovering downstream CAs from anchor %s/%s: %w",
				anchor.Kind, anchor.Name, err)
		}
		allCAs = append(allCAs, cas...)
	}

	// Deduplicate by namespace/name to avoid redundant CreateOrPatch calls
	// when a CA cert is reachable via multiple issuer anchors.
	seen := make(map[string]struct{}, len(allCAs))
	dedupedCAs := allCAs[:0]
	for _, ca := range allCAs {
		key := ca.Namespace + "/" + ca.Name
		if _, ok := seen[key]; !ok {
			seen[key] = struct{}{}
			dedupedCAs = append(dedupedCAs, ca)
		}
	}
	allCAs = dedupedCAs

	// 4. For each discovered CA cert, create-or-update a child PKIRotation CR.
	for i := range allCAs {
		cert := &allCAs[i]
		if err := r.ensureChildPKIR(ctx, rootPKIR, cert); err != nil {
			return fmt.Errorf("ensuring child PKIRotation for %s/%s: %w",
				cert.Namespace, cert.Name, err)
		}
	}

	return nil
}

// ensureChildPKIR creates or updates a child PKIRotation CR for the given intermediate CA cert.
func (r *PKIRotationReconciler) ensureChildPKIR(
	ctx context.Context, rootPKIR *platformv1alpha1.PKIRotation, cert *cmv1.Certificate,
) error {
	childName := intermediateChildName(rootPKIR.Name, cert.Namespace, cert.Name)

	child := &platformv1alpha1.PKIRotation{
		ObjectMeta: metav1.ObjectMeta{
			Name: childName,
		},
	}

	result, err := controllerutil.CreateOrPatch(ctx, r.Client, child, func() error {
		child.Spec = platformv1alpha1.PKIRotationSpec{
			Role:        platformv1alpha1.RoleIntermediateCA,
			RootCA:      rootPKIR.Spec.RootCA,
			TrustBundle: rootPKIR.Spec.TrustBundle,
			IntermediateCA: &platformv1alpha1.IntermediateCARef{
				CertificateName:      cert.Name,
				CertificateNamespace: cert.Namespace,
			},
		}
		// Apply the owner label for efficient label-based list filtering in syncChildSKIDs.
		if child.Labels == nil {
			child.Labels = make(map[string]string)
		}
		child.Labels[ownerPKIRLabel] = rootPKIR.Name
		// Ensure the owner reference is present without clobbering any other owner references.
		ownerRef := metav1.OwnerReference{
			APIVersion:         pkirotationAPIVersion,
			Kind:               pkirotationKind,
			Name:               rootPKIR.Name,
			UID:                rootPKIR.UID,
			Controller:         new(true),
			BlockOwnerDeletion: new(false), // false: cluster-scoped owner+child; no finalizer needed
		}
		found := false
		for _, ref := range child.OwnerReferences {
			if ref.Kind == pkirotationKind && ref.Name == rootPKIR.Name {
				found = true
				break
			}
		}
		if !found {
			child.OwnerReferences = append(child.OwnerReferences, ownerRef)
		}
		return nil
	})
	if err != nil {
		return fmt.Errorf("create-or-patch child PKIRotation %s: %w", childName, err)
	}

	// 5. Bootstrap SKID on first creation: if the intermediate CA Secret already
	// exists, set status.currentSKID so it does not false-trigger a cascade.
	if result == controllerutil.OperationResultCreated {
		skid, skidErr := r.intermediateSKID(ctx, child)
		if skidErr == nil && skid != "" {
			child.Status.CurrentSKID = skid
			if updateErr := r.Status().Update(ctx, child); updateErr != nil {
				// Non-fatal: the child's reconcileIdleIntermediate will record the SKID on its first run.
				// Log at Warning so persistent permission failures (e.g. missing RBAC) are visible.
				log := logf.FromContext(ctx)
				log.Error(updateErr, "failed to set bootstrap SKID on child IntermediateCA PKIRotation",
					"child", child.Name, "skid", skid)
			}
		}
	}

	return nil
}

// intermediateChildName computes the deterministic name for a child PKIRotation CR.
//
// Format: <parentName>-<sha256hex8>
// where sha256hex8 is the first 8 hex characters of sha256(namespace+"/"+name).
// The total name is truncated to 63 characters (Kubernetes DNS label limit).
func intermediateChildName(parentName, certNamespace, certName string) string {
	key := certNamespace + "/" + certName
	sum := sha256.Sum256([]byte(key))
	hash := fmt.Sprintf("%x", sum)[:hashSuffixLen]

	// Suffix is always "-<hash>": 1 + hashSuffixLen = 9 chars.
	// Parent name must not exceed 63 - 9 = 54 chars.
	const maxParent = maxPKIRNameLen - 1 - hashSuffixLen // 54
	if len(parentName) > maxParent {
		parentName = parentName[:maxParent]
	}
	return parentName + "-" + hash
}

// syncChildSKIDs updates status.currentSKID on every child IntermediateCA PKIRotation
// to match the SKID currently in each intermediate CA's Secret.
// Called from reconcileComplete (root rotation) after chain verification passes,
// to prevent child CRs from triggering spurious cascades when they resume from yield.
func (r *PKIRotationReconciler) syncChildSKIDs(ctx context.Context, rootPKIR *platformv1alpha1.PKIRotation) error {
	log := logf.FromContext(ctx)

	var all platformv1alpha1.PKIRotationList
	if err := r.List(ctx, &all, client.MatchingLabels{ownerPKIRLabel: rootPKIR.Name}); err != nil {
		return fmt.Errorf("listing child PKIRotation CRs: %w", err)
	}

	for i := range all.Items {
		child := &all.Items[i]

		// Skip the root CR itself.
		if child.Name == rootPKIR.Name {
			continue
		}

		// Only process IntermediateCA CRs owned by rootPKIR.
		if child.Spec.Role != platformv1alpha1.RoleIntermediateCA {
			continue
		}
		owned := false
		for _, ref := range child.OwnerReferences {
			if ref.Kind == pkirotationKind && ref.Name == rootPKIR.Name && ref.UID == rootPKIR.UID {
				owned = true
				break
			}
		}
		if !owned {
			continue
		}

		newSKID, err := r.intermediateSKID(ctx, child)
		if err != nil {
			// Non-fatal: log and continue — one missing Secret must not block the others.
			log.Error(err, "failed to read intermediate CA SKID for syncChildSKIDs; skipping",
				"child", child.Name)
			continue
		}

		if child.Status.CurrentSKID == newSKID {
			// Already in sync — no update needed.
			continue
		}

		child.Status.CurrentSKID = newSKID
		// Only clear PreviousSKID when the child is idle or complete.
		// Mid-cascade phases (e.g. AwaitingReissuance) own their own PreviousSKID
		// lifecycle via reconcileCompleteIntermediate; clearing it here would
		// corrupt the dual-trust window state machine.
		if child.Status.Phase == "" || child.Status.Phase == platformv1alpha1.PhaseIdle ||
			child.Status.Phase == platformv1alpha1.PhaseComplete {
			child.Status.PreviousSKID = ""
		}
		if updateErr := r.Status().Update(ctx, child); updateErr != nil {
			// Non-fatal: log and continue — don't abort the whole sync.
			log.Error(updateErr, "failed to update child IntermediateCA SKID in syncChildSKIDs",
				"child", child.Name, "skid", newSKID)
		}
	}

	return nil
}
