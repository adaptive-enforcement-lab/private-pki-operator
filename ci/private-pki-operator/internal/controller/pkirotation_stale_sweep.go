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
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client"
	logf "sigs.k8s.io/controller-runtime/pkg/log"

	platformv1alpha1 "github.com/adaptive-enforcement-lab/private-pki-operator/ci/private-pki-operator/api/v1alpha1"
)

// staleDownstreamSweepInterval is how often an Idle PKIRotation re-checks its direct
// children. A cascade only runs on an observed SKID change; a CA rotated before install
// or during downtime leaves children signed by an untracked key until they expire.
const staleDownstreamSweepInterval = time.Hour

// sweepStaleDirectChildren re-issues every direct child of caCert not signed by caSKID.
// Grandchildren carry their own parent's AKID and are swept by that CA's PKIRotation;
// children not Ready, already issuing, or without an AKID are left to cert-manager.
func (r *PKIRotationReconciler) sweepStaleDirectChildren(
	ctx context.Context, pkir *platformv1alpha1.PKIRotation, caCert *cmv1.Certificate, caSKID string,
) (int, error) {
	log := logf.FromContext(ctx)

	anchors, err := r.findIssuersForCACert(ctx, caCert)
	if err != nil {
		return 0, fmt.Errorf("finding issuers for CA %s/%s: %w", caCert.Namespace, caCert.Name, err)
	}
	anchors = anchorsResolvingToSecret(anchors, caCert, pkir.Spec.RootCA.CertificateNamespace)

	children, err := r.directChildren(ctx, anchors)
	if err != nil {
		return 0, err
	}

	triggered := 0
	for i := range children {
		child := &children[i]
		if !isCertificateResourceReady(child) || isCertificateIssuingTrue(child) {
			continue
		}
		akid, err := r.certificateAKID(ctx, child)
		if err != nil {
			log.Error(err, "reading child AKID; skipping", "certificate", client.ObjectKeyFromObject(child))
			continue
		}
		if akid == "" || akid == caSKID {
			continue
		}
		if err := r.triggerReissuance(ctx, child); err != nil {
			return triggered, fmt.Errorf("triggering reissuance for stale child %s/%s: %w",
				child.Namespace, child.Name, err)
		}
		triggered++
		log.Info("child signed by a previous CA key — triggered re-issuance",
			"certificate", client.ObjectKeyFromObject(child), "akid", akid, "caSkid", caSKID)
		r.Recorder.Eventf(pkir, corev1.EventTypeWarning, "StaleDownstreamReissuanceTriggered",
			"%s/%s is signed by key %s, not the current CA key %s; triggered re-issuance",
			child.Namespace, child.Name, akid, caSKID)
	}
	recordStaleDownstreamReissued(pkir, triggered)
	return triggered, nil
}

// anchorsResolvingToSecret drops issuers that only share caCert's Secret NAME: Issuers
// resolve it in their own namespace, ClusterIssuers in the root CA's. Judging a different
// CA's certificates against this SKID would re-issue them on every sweep.
func anchorsResolvingToSecret(
	anchors []issuerAnchor, caCert *cmv1.Certificate, clusterResourceNamespace string,
) []issuerAnchor {
	kept := anchors[:0:0]
	for _, a := range anchors {
		switch a.Kind {
		case issuerKindClusterIssuer:
			if caCert.Namespace != clusterResourceNamespace {
				continue
			}
		case issuerKindIssuer:
			if a.Namespace != caCert.Namespace {
				continue
			}
		}
		kept = append(kept, a)
	}
	return kept
}

// directChildren lists the Certificates issued directly by any of the anchors.
func (r *PKIRotationReconciler) directChildren(
	ctx context.Context, anchors []issuerAnchor,
) ([]cmv1.Certificate, error) {
	var children []cmv1.Certificate
	for _, anchor := range anchors {
		var list cmv1.CertificateList
		var opts []client.ListOption
		if anchor.Kind == issuerKindIssuer {
			opts = append(opts, client.InNamespace(anchor.Namespace))
		}
		if err := r.List(ctx, &list, opts...); err != nil {
			return nil, fmt.Errorf("listing Certificates for %s/%s: %w", anchor.Kind, anchor.Name, err)
		}
		for _, cert := range list.Items {
			if cert.Spec.IssuerRef.Name == anchor.Name && cert.Spec.IssuerRef.Kind == anchor.Kind {
				children = append(children, cert)
			}
		}
	}
	return children, nil
}

// sweepIntermediateChildren runs the stale-child sweep for a role=IntermediateCA
// PKIRotation whose recorded SKID matches the live intermediate.
func (r *PKIRotationReconciler) sweepIntermediateChildren(
	ctx context.Context, pkir *platformv1alpha1.PKIRotation,
) (time.Duration, error) {
	intCert, err := r.loadIntermediateCert(ctx, pkir)
	if err != nil {
		return 0, err
	}
	if _, err := r.sweepStaleDirectChildren(ctx, pkir, intCert, pkir.Status.CurrentSKID); err != nil {
		return 0, err
	}
	return staleDownstreamSweepInterval, nil
}

// sweepRootChildren runs the stale-child sweep for a role=RootCA PKIRotation
// whose recorded SKID matches the live root.
func (r *PKIRotationReconciler) sweepRootChildren(
	ctx context.Context, pkir *platformv1alpha1.PKIRotation,
) (time.Duration, error) {
	var rootCert cmv1.Certificate
	key := types.NamespacedName{Name: pkir.Spec.RootCA.CertificateName, Namespace: pkir.Spec.RootCA.CertificateNamespace}
	if err := r.Get(ctx, key, &rootCert); err != nil {
		return 0, fmt.Errorf("getting root CA Certificate %s: %w", key, err)
	}
	if _, err := r.sweepStaleDirectChildren(ctx, pkir, &rootCert, pkir.Status.CurrentSKID); err != nil {
		return 0, err
	}
	return staleDownstreamSweepInterval, nil
}
