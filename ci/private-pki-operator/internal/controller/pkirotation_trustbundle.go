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
	trustv1alpha1 "github.com/cert-manager/trust-manager/pkg/apis/trust/v1alpha1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client"

	platformv1alpha1 "github.com/adaptive-enforcement-lab/private-pki-operator/ci/private-pki-operator/api/v1alpha1"
	"github.com/adaptive-enforcement-lab/private-pki-operator/ci/private-pki-operator/internal/pki"
)

// The staging ConfigMap and the trust-manager Bundle that distribute the trust
// anchors. The dual-trust window is exactly the period this ConfigMap carries
// both the outgoing and the incoming root.

// extendStagingConfigMap appends the new root PEM to the staging ConfigMap
// so both old and new roots are present (dual-trust window).
func (r *PKIRotationReconciler) extendStagingConfigMap(ctx context.Context, pkir *platformv1alpha1.PKIRotation) error {
	// Read the new root PEM from the cert-manager Secret.
	var cert cmv1.Certificate
	if err := r.Get(ctx, types.NamespacedName{
		Name:      pkir.Spec.RootCA.CertificateName,
		Namespace: pkir.Spec.RootCA.CertificateNamespace,
	}, &cert); err != nil {
		return fmt.Errorf("getting root CA Certificate: %w", err)
	}
	var secret corev1.Secret
	if err := r.Get(ctx, types.NamespacedName{
		Name:      cert.Spec.SecretName,
		Namespace: pkir.Spec.RootCA.CertificateNamespace,
	}, &secret); err != nil {
		return fmt.Errorf("getting root CA Secret: %w", err)
	}
	newRootPEM, ok := secret.Data["tls.crt"]
	if !ok {
		return fmt.Errorf("root CA Secret missing tls.crt")
	}

	// Get and patch the staging ConfigMap.
	var cm corev1.ConfigMap
	if err := r.Get(ctx, types.NamespacedName{
		Name:      pkir.Spec.TrustBundle.StagingConfigMap.Name,
		Namespace: pkir.Spec.TrustBundle.StagingConfigMap.Namespace,
	}, &cm); err != nil {
		return fmt.Errorf("getting staging ConfigMap: %w", err)
	}

	patch := client.MergeFrom(cm.DeepCopy())
	if cm.Data == nil {
		cm.Data = make(map[string]string)
	}
	existing := []byte(cm.Data[trustBundleKey])
	cm.Data[trustBundleKey] = string(pki.AppendPEM(existing, newRootPEM))
	return r.Patch(ctx, &cm, patch)
}

// trimStagingConfigMap removes the old root PEM from the staging ConfigMap,
// leaving only the new root (rotation complete).
func (r *PKIRotationReconciler) trimStagingConfigMap(ctx context.Context, pkir *platformv1alpha1.PKIRotation) error {
	if pkir.Status.PreviousSKID == "" {
		// Nothing to remove — idempotent no-op.
		return nil
	}

	var cm corev1.ConfigMap
	if err := r.Get(ctx, types.NamespacedName{
		Name:      pkir.Spec.TrustBundle.StagingConfigMap.Name,
		Namespace: pkir.Spec.TrustBundle.StagingConfigMap.Namespace,
	}, &cm); err != nil {
		return fmt.Errorf("getting staging ConfigMap: %w", err)
	}

	existing := []byte(cm.Data[trustBundleKey])
	trimmed, err := pki.RemovePEMBySKID(existing, pkir.Status.PreviousSKID)
	if err != nil {
		return fmt.Errorf("removing old root PEM: %w", err)
	}

	patch := client.MergeFrom(cm.DeepCopy())
	cm.Data[trustBundleKey] = string(trimmed)
	return r.Patch(ctx, &cm, patch)
}

// ensureStagingConfigMap creates the staging ConfigMap if it does not exist,
// seeded with the current root CA PEM. If it already exists it is left unchanged.
// The ConfigMap is owned by the operator for the lifetime of the PKIRotation.
func (r *PKIRotationReconciler) ensureStagingConfigMap(ctx context.Context, pkir *platformv1alpha1.PKIRotation) error {
	var cm corev1.ConfigMap
	err := r.Get(ctx, types.NamespacedName{
		Name:      pkir.Spec.TrustBundle.StagingConfigMap.Name,
		Namespace: pkir.Spec.TrustBundle.StagingConfigMap.Namespace,
	}, &cm)
	if client.IgnoreNotFound(err) != nil {
		return fmt.Errorf("checking for staging ConfigMap: %w", err)
	}
	if err == nil {
		// Already exists — leave it unchanged.
		return nil
	}

	// Seed with the current root CA PEM.
	var cert cmv1.Certificate
	if err := r.Get(ctx, types.NamespacedName{
		Name:      pkir.Spec.RootCA.CertificateName,
		Namespace: pkir.Spec.RootCA.CertificateNamespace,
	}, &cert); err != nil {
		return fmt.Errorf("getting root CA Certificate: %w", err)
	}
	var secret corev1.Secret
	if err := r.Get(ctx, types.NamespacedName{
		Name:      cert.Spec.SecretName,
		Namespace: pkir.Spec.RootCA.CertificateNamespace,
	}, &secret); err != nil {
		return fmt.Errorf("getting root CA Secret: %w", err)
	}
	rootPEM, ok := secret.Data["tls.crt"]
	if !ok {
		return fmt.Errorf("root CA Secret missing tls.crt")
	}

	newCM := &corev1.ConfigMap{
		ObjectMeta: metav1.ObjectMeta{
			Name:      pkir.Spec.TrustBundle.StagingConfigMap.Name,
			Namespace: pkir.Spec.TrustBundle.StagingConfigMap.Namespace,
			Labels: map[string]string{
				"app.kubernetes.io/name":      "private-pki-operator",
				"app.kubernetes.io/component": "trust-anchor",
			},
			Annotations: map[string]string{
				"description": "Sole staging area for root CA PEMs during rotation. Managed by private-pki-operator.",
			},
		},
		Data: map[string]string{trustBundleKey: string(rootPEM)},
	}
	return r.Create(ctx, newCM)
}

// ensureBundle creates the trust-manager Bundle sourcing from the staging ConfigMap
// if it does not exist. If the Bundle already exists with the correct source it is
// left unchanged. If the source is incorrect (e.g. legacy Secret source), it is
// patched to point at the staging ConfigMap.
func (r *PKIRotationReconciler) ensureBundle(ctx context.Context, pkir *platformv1alpha1.PKIRotation) error {
	wantSource := trustv1alpha1.BundleSource{
		ConfigMap: &trustv1alpha1.SourceObjectKeySelector{
			Name: pkir.Spec.TrustBundle.StagingConfigMap.Name,
			Key:  trustBundleKey,
		},
	}

	var bundle trustv1alpha1.Bundle
	err := r.Get(ctx, types.NamespacedName{Name: pkir.Spec.TrustBundle.Name}, &bundle)
	if client.IgnoreNotFound(err) != nil {
		return fmt.Errorf("checking for Bundle: %w", err)
	}
	if err == nil {
		// Exists — check if source is already the staging ConfigMap.
		if len(bundle.Spec.Sources) == 1 &&
			bundle.Spec.Sources[0].ConfigMap != nil &&
			bundle.Spec.Sources[0].ConfigMap.Name == pkir.Spec.TrustBundle.StagingConfigMap.Name &&
			bundle.Spec.Sources[0].ConfigMap.Key == trustBundleKey {
			return nil // Already correct.
		}
		// Source is wrong (legacy Secret or different ConfigMap) — patch it.
		base := bundle.DeepCopy()
		bundle.Spec.Sources = []trustv1alpha1.BundleSource{wantSource}
		return r.Patch(ctx, &bundle, client.MergeFrom(base))
	}

	// Does not exist — create it.
	newBundle := &trustv1alpha1.Bundle{
		ObjectMeta: metav1.ObjectMeta{
			Name: pkir.Spec.TrustBundle.Name,
			Labels: map[string]string{
				"app.kubernetes.io/name":      "private-pki-operator",
				"app.kubernetes.io/component": "trust-bundle",
			},
		},
		Spec: trustv1alpha1.BundleSpec{
			Sources: []trustv1alpha1.BundleSource{wantSource},
			Target: trustv1alpha1.BundleTarget{
				ConfigMap:         &trustv1alpha1.TargetTemplate{Key: trustBundleKey},
				NamespaceSelector: &metav1.LabelSelector{},
			},
		},
	}
	return r.Create(ctx, newBundle)
}
