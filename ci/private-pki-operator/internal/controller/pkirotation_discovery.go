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

	cmv1 "github.com/cert-manager/cert-manager/pkg/apis/certmanager/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

const issuerKindIssuer = "Issuer"

// issuerAnchor identifies a cert-manager Issuer or ClusterIssuer.
// For ClusterIssuers, Namespace is empty. For Issuers, Namespace is the
// namespace the Issuer and its signed Certificates live in.
type issuerAnchor struct {
	Name      string
	Kind      string // "Issuer" or "ClusterIssuer"
	Namespace string // empty for ClusterIssuer
}

// discoverDownstream returns all Certificate objects below anchorIssuer at any
// chain depth, separated into CA certs (isCA=true) and leaf certs (isCA=false).
// It handles both Issuer and ClusterIssuer anchors.
//
// Algorithm (BFS):
//  1. List all Certificates where spec.issuerRef matches anchor (name + kind).
//     For namespace-scoped Issuers, restrict to the Issuer's namespace.
//  2. For each result:
//     - isCA=false → collect as leaf, do not recurse.
//     - isCA=true → collect as CA, then find all Issuers/ClusterIssuers backed by
//     that cert's Secret via findIssuersForCACert, recurse into each.
//  3. Terminate when no CA certs are found at a level.
func (r *PKIRotationReconciler) discoverDownstream(
	ctx context.Context, anchor issuerAnchor,
) (cas []cmv1.Certificate, leaves []cmv1.Certificate, err error) {
	return r.discoverDownstreamBFS(ctx, []issuerAnchor{anchor})
}

func (r *PKIRotationReconciler) discoverDownstreamBFS(
	ctx context.Context, anchors []issuerAnchor,
) (cas []cmv1.Certificate, leaves []cmv1.Certificate, err error) {
	if len(anchors) == 0 {
		return nil, nil, nil
	}

	var nextAnchors []issuerAnchor

	for _, anchor := range anchors {
		var certList cmv1.CertificateList
		var listOpts []client.ListOption
		if anchor.Kind == issuerKindIssuer && anchor.Namespace != "" {
			listOpts = append(listOpts, client.InNamespace(anchor.Namespace))
		}
		if err := r.List(ctx, &certList, listOpts...); err != nil {
			return nil, nil, fmt.Errorf("listing Certificates for anchor %s/%s: %w", anchor.Kind, anchor.Name, err)
		}

		for _, cert := range certList.Items {
			if cert.Spec.IssuerRef.Name != anchor.Name || cert.Spec.IssuerRef.Kind != anchor.Kind {
				continue
			}
			// For namespace Issuers, the cert must be in the same namespace.
			if anchor.Kind == issuerKindIssuer && anchor.Namespace != "" && cert.Namespace != anchor.Namespace {
				continue
			}

			if !cert.Spec.IsCA {
				leaves = append(leaves, cert)
				continue
			}

			cas = append(cas, cert)

			// Find all Issuers/ClusterIssuers backed by this CA cert's Secret.
			childAnchors, err := r.findIssuersForCACert(ctx, &cert)
			if err != nil {
				return nil, nil, fmt.Errorf("finding issuers for CA cert %s/%s: %w", cert.Namespace, cert.Name, err)
			}
			nextAnchors = append(nextAnchors, childAnchors...)
		}
	}

	// Recurse into the next BFS level.
	childCAs, childLeaves, err := r.discoverDownstreamBFS(ctx, nextAnchors)
	if err != nil {
		return nil, nil, err
	}

	return append(cas, childCAs...), append(leaves, childLeaves...), nil
}

// findIssuersForCACert finds all Issuers and ClusterIssuers whose spec.ca.secretName
// matches the given CA Certificate's spec.secretName. These become the anchors for
// the next BFS level.
//
// The issuer that signed the CA cert itself (caCert.Spec.IssuerRef) is excluded to
// prevent infinite recursion — that issuer is already an ancestor in the chain.
func (r *PKIRotationReconciler) findIssuersForCACert(
	ctx context.Context, caCert *cmv1.Certificate,
) ([]issuerAnchor, error) {
	var anchors []issuerAnchor

	// ClusterIssuers: cluster-wide, no namespace restriction.
	var clusterIssuers cmv1.ClusterIssuerList
	if err := r.List(ctx, &clusterIssuers); err != nil {
		return nil, fmt.Errorf("listing ClusterIssuers: %w", err)
	}
	for _, ci := range clusterIssuers.Items {
		if ci.Spec.CA == nil || ci.Spec.CA.SecretName != caCert.Spec.SecretName {
			continue
		}
		// Skip the issuer that signed this CA cert — it is already an ancestor.
		if ci.Name == caCert.Spec.IssuerRef.Name && caCert.Spec.IssuerRef.Kind == issuerKindClusterIssuer {
			continue
		}
		anchors = append(anchors, issuerAnchor{
			Name: ci.Name,
			Kind: issuerKindClusterIssuer,
		})
	}

	// Namespace Issuers: list cluster-wide because a namespace Issuer in any namespace
	// may reference this CA's Secret (cert-manager resolves secrets across namespaces
	// for CA issuers). Match by secretName only; namespace is taken from the Issuer.
	var issuers cmv1.IssuerList
	if err := r.List(ctx, &issuers); err != nil {
		return nil, fmt.Errorf("listing Issuers: %w", err)
	}
	for _, iss := range issuers.Items {
		if iss.Spec.CA == nil || iss.Spec.CA.SecretName != caCert.Spec.SecretName {
			continue
		}
		// Skip the issuer that signed this CA cert — it is already an ancestor.
		if iss.Name == caCert.Spec.IssuerRef.Name &&
			iss.Namespace == caCert.Namespace &&
			caCert.Spec.IssuerRef.Kind == issuerKindIssuer {
			continue
		}
		anchors = append(anchors, issuerAnchor{
			Name:      iss.Name,
			Kind:      issuerKindIssuer,
			Namespace: iss.Namespace,
		})
	}

	return anchors, nil
}
