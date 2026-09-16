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

	apiutil "github.com/cert-manager/cert-manager/pkg/api/util"
	cmv1 "github.com/cert-manager/cert-manager/pkg/apis/certmanager/v1"
	cmmeta "github.com/cert-manager/cert-manager/pkg/apis/meta/v1"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client"

	platformv1alpha1 "github.com/adaptive-enforcement-lab/private-pki-operator/ci/private-pki-operator/api/v1alpha1"
	"github.com/adaptive-enforcement-lab/private-pki-operator/ci/private-pki-operator/internal/pki"
)

// Reads and writes against cert-manager Certificates: locating the tier-1,
// tier-2 and leaf certificates a rotation touches, inspecting their key
// identifiers and readiness, and triggering reissuance.

// currentRootSKID reads the root CA Secret and returns its Subject Key Identifier.
// Only a named get is performed — no list/watch on Secrets.
func (r *PKIRotationReconciler) currentRootSKID(
	ctx context.Context, pkir *platformv1alpha1.PKIRotation,
) (string, error) {
	var cert cmv1.Certificate
	if err := r.Get(ctx, types.NamespacedName{
		Name:      pkir.Spec.RootCA.CertificateName,
		Namespace: pkir.Spec.RootCA.CertificateNamespace,
	}, &cert); err != nil {
		return "", fmt.Errorf("getting root CA Certificate: %w", err)
	}

	var secret corev1.Secret
	if err := r.Get(ctx, types.NamespacedName{
		Name:      cert.Spec.SecretName,
		Namespace: pkir.Spec.RootCA.CertificateNamespace,
	}, &secret); err != nil {
		return "", fmt.Errorf("getting root CA Secret %s: %w", cert.Spec.SecretName, err)
	}

	certPEM, ok := secret.Data["tls.crt"]
	if !ok {
		return "", fmt.Errorf("secret %s missing tls.crt key", cert.Spec.SecretName)
	}
	return pki.SKIDFromPEM(certPEM)
}

// discoverIntermediates finds all cert-manager Certificates whose issuerRef
// points to the ClusterIssuer backed by the root CA Secret.
func (r *PKIRotationReconciler) discoverIntermediates(
	ctx context.Context, pkir *platformv1alpha1.PKIRotation,
) ([]cmv1.Certificate, error) {
	// Step 1: find the ClusterIssuer backed by the root CA Secret.
	var cert cmv1.Certificate
	if err := r.Get(ctx, types.NamespacedName{
		Name:      pkir.Spec.RootCA.CertificateName,
		Namespace: pkir.Spec.RootCA.CertificateNamespace,
	}, &cert); err != nil {
		return nil, fmt.Errorf("getting root CA Certificate: %w", err)
	}

	var issuers cmv1.ClusterIssuerList
	if err := r.List(ctx, &issuers); err != nil {
		return nil, fmt.Errorf("listing ClusterIssuers: %w", err)
	}

	var rootIssuerName string
	for _, issuer := range issuers.Items {
		if issuer.Spec.CA != nil && issuer.Spec.CA.SecretName == cert.Spec.SecretName {
			rootIssuerName = issuer.Name
			break
		}
	}
	if rootIssuerName == "" {
		return nil, fmt.Errorf("no ClusterIssuer found with ca.secretName=%s", cert.Spec.SecretName)
	}

	// Step 2: find all Certificates whose issuerRef points to that ClusterIssuer.
	var certs cmv1.CertificateList
	if err := r.List(ctx, &certs); err != nil {
		return nil, fmt.Errorf("listing Certificates: %w", err)
	}

	var intermediates []cmv1.Certificate
	for _, c := range certs.Items {
		if c.Spec.IssuerRef.Name == rootIssuerName &&
			c.Spec.IssuerRef.Kind == issuerKindClusterIssuer &&
			c.Spec.IsCA {
			intermediates = append(intermediates, c)
		}
	}
	return intermediates, nil
}

// discoverNamespaceIntermediates finds namespace-scoped isCA Certificates whose
// issuerRef points to a ClusterIssuer backed by one of the tier-1 intermediate
// CA Secrets. These are the workload-namespace intermediate CAs that must be
// re-issued after the cluster intermediate is rotated.
func (r *PKIRotationReconciler) discoverNamespaceIntermediates(
	ctx context.Context, tier1 []cmv1.Certificate,
) ([]cmv1.Certificate, error) {
	if len(tier1) == 0 {
		return nil, nil
	}

	// Build a set of Secret names backing the tier-1 intermediates.
	tier1Secrets := make(map[string]bool, len(tier1))
	for _, c := range tier1 {
		tier1Secrets[c.Spec.SecretName] = true
	}

	// Find ClusterIssuers backed by those Secrets (e.g. private-intermediate-ca).
	var issuers cmv1.ClusterIssuerList
	if err := r.List(ctx, &issuers); err != nil {
		return nil, fmt.Errorf("listing ClusterIssuers: %w", err)
	}
	tier1IssuerNames := make(map[string]bool)
	for _, issuer := range issuers.Items {
		if issuer.Spec.CA != nil && tier1Secrets[issuer.Spec.CA.SecretName] {
			tier1IssuerNames[issuer.Name] = true
		}
	}
	if len(tier1IssuerNames) == 0 {
		return nil, nil
	}

	// List all Certificates cluster-wide (cache expanded in cmd/main.go).
	var all cmv1.CertificateList
	if err := r.List(ctx, &all); err != nil {
		return nil, fmt.Errorf("listing Certificates: %w", err)
	}

	var result []cmv1.Certificate
	for _, c := range all.Items {
		if c.Spec.IsCA &&
			c.Spec.IssuerRef.Kind == issuerKindClusterIssuer &&
			tier1IssuerNames[c.Spec.IssuerRef.Name] {
			result = append(result, c)
		}
	}
	return result, nil
}

// latestNotBefore returns the latest status.NotBefore time among the given
// Certificates. Returns the zero time if none have NotBefore populated.
func latestNotBefore(certs []cmv1.Certificate) time.Time {
	var latest time.Time
	for _, c := range certs {
		if c.Status.NotBefore != nil && c.Status.NotBefore.After(latest) {
			latest = c.Status.NotBefore.Time
		}
	}
	return latest
}

// isCertificateResourceReady returns true when the Certificate has a Ready=True condition.
func isCertificateResourceReady(cert *cmv1.Certificate) bool {
	for _, cond := range cert.Status.Conditions {
		if cond.Type == cmv1.CertificateConditionReady {
			return cond.Status == cmmeta.ConditionTrue
		}
	}
	return false
}

// isCertificateIssuingTrue returns true when cert-manager has already set
// Issuing=True on the Certificate, meaning reissuance is already in flight.
// If True, skip re-triggering to avoid reconcile feedback loops; just requeue.
func isCertificateIssuingTrue(cert *cmv1.Certificate) bool {
	for _, cond := range cert.Status.Conditions {
		if cond.Type == cmv1.CertificateConditionIssuing {
			return cond.Status == cmmeta.ConditionTrue
		}
	}
	return false
}

// discoverLeafCerts finds non-isCA Certificates that belong to our PKI hierarchy.
// It covers two scopes:
//
//  1. All non-isCA Certificates in namespaces that contain a tier-2 intermediate
//     CA. These are issued by namespace Issuers backed by the namespace intermediate
//     CA Secrets (e.g. chaos-mesh-cert via chaos-mesh-ca Issuer).
//
//  2. Non-isCA Certificates in the cert-manager namespace issued by a ClusterIssuer
//     backed by a tier-1 intermediate CA Secret (e.g. trust-manager webhook cert).
//
// cert-manager does not auto-cascade re-issuance from intermediate key changes to
// leaf certs, so the operator must trigger each one explicitly after all
// intermediate CAs have been confirmed re-issued.
func (r *PKIRotationReconciler) discoverLeafCerts(
	ctx context.Context, tier1, tier2 []cmv1.Certificate,
) ([]cmv1.Certificate, error) {
	// Namespaces that contain tier-2 intermediates hold our workload leaf certs.
	tier2Namespaces := make(map[string]bool, len(tier2))
	for _, c := range tier2 {
		tier2Namespaces[c.Namespace] = true
	}

	// ClusterIssuers backed by tier-1 Secrets issue certs directly in the
	// cert-manager namespace (e.g. trust-manager webhook cert).
	tier1Secrets := make(map[string]bool, len(tier1))
	for _, c := range tier1 {
		tier1Secrets[c.Spec.SecretName] = true
	}
	var issuers cmv1.ClusterIssuerList
	if err := r.List(ctx, &issuers); err != nil {
		return nil, fmt.Errorf("listing ClusterIssuers: %w", err)
	}
	tier1IssuerNames := make(map[string]bool)
	for _, issuer := range issuers.Items {
		if issuer.Spec.CA != nil && tier1Secrets[issuer.Spec.CA.SecretName] {
			tier1IssuerNames[issuer.Name] = true
		}
	}

	var all cmv1.CertificateList
	if err := r.List(ctx, &all); err != nil {
		return nil, fmt.Errorf("listing Certificates: %w", err)
	}

	var result []cmv1.Certificate
	for _, c := range all.Items {
		if c.Spec.IsCA {
			continue
		}
		// Leaf certs in tier-2 namespaces (workload namespace intermediates).
		if tier2Namespaces[c.Namespace] {
			result = append(result, c)
			continue
		}
		// Leaf certs in any namespace issued by a tier-1 ClusterIssuer directly.
		if c.Spec.IssuerRef.Kind == issuerKindClusterIssuer && tier1IssuerNames[c.Spec.IssuerRef.Name] {
			result = append(result, c)
		}
	}
	return result, nil
}

// triggerReissuance instructs cert-manager to immediately re-issue an intermediate
// CA by setting an Issuing=True condition on the Certificate's status subresource.
// This is the same mechanism used by cmctl renew: cert-manager's trigger controller
// watches for Issuing=True and creates a new CertificateRequest within seconds.
// This is idempotent: if Issuing is already True, SetCertificateCondition does not
// update LastTransitionTime, and the patch is a no-op.
func (r *PKIRotationReconciler) triggerReissuance(ctx context.Context, cert *cmv1.Certificate) error {
	base := cert.DeepCopy()
	apiutil.SetCertificateCondition(
		cert, cert.Generation, cmv1.CertificateConditionIssuing, cmmeta.ConditionTrue,
		"ManuallyTriggered", "Certificate re-issuance triggered by PKI rotation operator",
	)
	return r.Status().Patch(ctx, cert, client.MergeFrom(base))
}

// clearReissuanceTrigger is a no-op: cert-manager automatically clears the
// Issuing condition on the Certificate after completing reissuance.
// No cleanup is needed by the operator.
func (r *PKIRotationReconciler) clearReissuanceTrigger(_ context.Context, _ *platformv1alpha1.PKIRotation) error {
	return nil
}

// certificateAKID reads the Certificate's backing Secret and returns the
// Authority Key Identifier of the issued certificate.
// Returns ("", nil) when the Secret is absent — cert-manager is mid-reissuance;
// the caller should treat an empty AKID as "not yet reissued".
func (r *PKIRotationReconciler) certificateAKID(ctx context.Context, cert *cmv1.Certificate) (string, error) {
	var secret corev1.Secret
	// Use uncached reader: cert Secrets can live in any namespace (chaos-mesh,
	// any workload namespace) outside the cache's cert-manager restriction.
	if err := r.getReader().Get(ctx, types.NamespacedName{
		Name:      cert.Spec.SecretName,
		Namespace: cert.Namespace,
	}, &secret); err != nil {
		return "", client.IgnoreNotFound(err) // "" + nil when Secret is temporarily absent
	}
	certPEM, ok := secret.Data["tls.crt"]
	if !ok {
		return "", fmt.Errorf("secret %s/%s missing tls.crt key", cert.Namespace, cert.Spec.SecretName)
	}
	return pki.AKIDFromPEM(certPEM)
}
