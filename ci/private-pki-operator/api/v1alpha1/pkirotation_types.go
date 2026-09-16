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

package v1alpha1

import (
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// PKIRotationPhase represents the current state of a root CA rotation.
//
// +kubebuilder:validation:Enum=Idle;PreservingOldRoot;DualTrustActive;AwaitingReissuance;VerifyingChain;Complete
//
//nolint:lll // the kubebuilder Enum marker must stay on one line
type PKIRotationPhase string

const (
	// PhaseIdle means no rotation is in progress. The staging ConfigMap holds
	// only the current root PEM and the Bundle sources from it.
	PhaseIdle PKIRotationPhase = "Idle"

	// PhasePreservingOldRoot means a CertificateRequest for the root CA has been
	// detected. The operator has recorded the previous root SKID. The staging
	// ConfigMap still holds only the old root PEM — it has not yet changed.
	PhasePreservingOldRoot PKIRotationPhase = "PreservingOldRoot"

	// PhaseDualTrustActive means the root CA Secret has been updated with the new
	// cert. The operator has appended the new root PEM to the staging ConfigMap.
	// Both old and new roots are now trusted. The operator has triggered re-issuance
	// of all discovered intermediate CAs.
	PhaseDualTrustActive PKIRotationPhase = "DualTrustActive"

	// PhaseAwaitingReissuance means intermediate re-issuance has been triggered.
	// The operator is waiting for cert-manager to complete renewal of all
	// discovered intermediate CAs with the correct AKID.
	PhaseAwaitingReissuance PKIRotationPhase = "AwaitingReissuance"

	// PhaseVerifyingChain means all discovered intermediates have been renewed.
	// The operator is performing a full AKID→SKID chain walk to confirm correctness.
	PhaseVerifyingChain PKIRotationPhase = "VerifyingChain"

	// PhaseComplete means the chain is verified. The operator is removing the old
	// root PEM from the staging ConfigMap and returning to Idle.
	PhaseComplete PKIRotationPhase = "Complete"
)

// Condition type constants for PKIRotation.
const (
	// ConditionDualTrustActive is True when the staging ConfigMap contains both
	// the old and new root CA PEMs and trust-manager has distributed both.
	ConditionDualTrustActive = "DualTrustActive"

	// ConditionIntermediateReissued reports that the re-issuance this rotation
	// triggered has landed. Its subject differs per role, and that difference is
	// the whole of its semantics:
	//
	//   role=RootCA          True when all discovered intermediate CAs have been
	//                        re-issued with an AKID matching the new root SKID.
	//   role=IntermediateCA  True when every downstream cert (CA and leaf) below
	//                        this intermediate has been re-issued after it rotated.
	//
	// In BOTH roles it reaches True on completion. It previously never did on the
	// IntermediateCA path, so a finished rotation permanently reported
	// AwaitingCertManagerRenewal alongside a ChainVerified=True that contradicted
	// it (issue #260). Read together with ConditionChainVerified: this condition
	// says the re-issuance happened, that one says the resulting chain checks out.
	ConditionIntermediateReissued = "IntermediateReissued"

	// ConditionChainVerified is True when the full AKID→SKID chain walk has
	// passed for all declared intermediate CAs.
	ConditionChainVerified = "ChainVerified"
)

// Condition reason constants.
const (
	ReasonAwaitingRootRenewal    = "AwaitingRootRenewal"
	ReasonStagingWriteFailed     = "StagingWriteFailed"
	ReasonBundlePatchFailed      = "BundlePatchFailed"
	ReasonAnnotationApplied      = "AnnotationApplied"
	ReasonAwaitingCertMgrRenewal = "AwaitingCertManagerRenewal"
	ReasonReissuancePending      = "ReissuancePending"
	ReasonAKIDMismatch           = "AKIDMismatch"
	ReasonSecretReadFailed       = "SecretReadFailed"
	ReasonVerified               = "Verified"
	// ReasonAllDownstreamReissued closes ConditionIntermediateReissued on the
	// IntermediateCA path. Distinct from the RootCA path's AllIntermediatesReissued
	// because the two count different things — intermediates below a root, versus
	// every downstream cert below an intermediate.
	ReasonAllDownstreamReissued = "AllDownstreamReissued"
)

// PKIRotationRole determines which phases of the state machine apply.
// +kubebuilder:validation:Enum=RootCA;IntermediateCA
type PKIRotationRole string

const (
	// RoleRootCA is the default role. Runs the full rotation state machine
	// including dual-trust window and cascade reissuance.
	RoleRootCA PKIRotationRole = "RootCA"

	// RoleIntermediateCA is managed automatically by the operator.
	// Runs a cascade-only state machine: Idle → AwaitingReissuance → VerifyingChain → Complete.
	// Do not declare IntermediateCA CRs manually.
	RoleIntermediateCA PKIRotationRole = "IntermediateCA"
)

// IntermediateCARef identifies the cert-manager Certificate representing an
// intermediate CA. Required when spec.role=IntermediateCA.
type IntermediateCARef struct {
	// certificateName is the name of the cert-manager Certificate object.
	// +required
	// +kubebuilder:validation:MinLength=1
	CertificateName string `json:"certificateName"`

	// certificateNamespace is the namespace of the cert-manager Certificate object.
	// +required
	// +kubebuilder:validation:MinLength=1
	CertificateNamespace string `json:"certificateNamespace"`
}

// RootCARef identifies the cert-manager Certificate resource representing the root CA.
type RootCARef struct {
	// certificateName is the name of the cert-manager Certificate object.
	// +required
	// +kubebuilder:validation:MinLength=1
	CertificateName string `json:"certificateName"`

	// certificateNamespace is the namespace of the cert-manager Certificate object.
	// +required
	// +kubebuilder:validation:MinLength=1
	CertificateNamespace string `json:"certificateNamespace"`
}

// StagingConfigMapRef identifies the ConfigMap the operator uses as the
// sole staging area for root CA PEMs during rotation. This ConfigMap must
// exist before the operator is deployed. It is never written by cert-manager.
type StagingConfigMapRef struct {
	// name is the name of the staging ConfigMap.
	// +required
	// +kubebuilder:validation:MinLength=1
	Name string `json:"name"`

	// namespace is the namespace of the staging ConfigMap. This must be the
	// trust-manager trust namespace (typically cert-manager).
	// +required
	// +kubebuilder:validation:MinLength=1
	Namespace string `json:"namespace"`
}

// TrustBundleRef identifies the trust-manager Bundle and its staging ConfigMap.
type TrustBundleRef struct {
	// name is the name of the trust-manager Bundle resource (cluster-scoped).
	// +required
	// +kubebuilder:validation:MinLength=1
	Name string `json:"name"`

	// stagingConfigMap is the separately curated ConfigMap that the Bundle
	// sources from. The operator writes root CA PEM(s) here during rotation.
	// +required
	StagingConfigMap StagingConfigMapRef `json:"stagingConfigMap"`
}

// PKIRotationSpec defines the desired state of PKIRotation.
type PKIRotationSpec struct {
	// rootCA identifies the cert-manager Certificate representing the root CA
	// whose rotation lifecycle this resource manages.
	// +required
	RootCA RootCARef `json:"rootCA"`

	// trustBundle identifies the trust-manager Bundle and staging ConfigMap
	// to manage during rotation. The Bundle must already source from the
	// staging ConfigMap before the operator takes effect.
	// +required
	TrustBundle TrustBundleRef `json:"trustBundle"`

	// reissuanceTimeout is the maximum duration the operator will wait for
	// cert-manager to complete intermediate CA re-issuance before emitting a
	// Warning event. The operator does not abort; it continues waiting.
	// Defaults to 15m.
	// +optional
	// +default="15m"
	ReissuanceTimeout metav1.Duration `json:"reissuanceTimeout,omitempty"`

	// role determines which phases of the state machine apply.
	// RootCA (default) runs the full rotation including dual-trust window.
	// IntermediateCA runs cascade-only: AwaitingReissuance → VerifyingChain.
	// IntermediateCA CRs are auto-created by the operator; do not declare them manually.
	// +default="RootCA"
	// +optional
	Role PKIRotationRole `json:"role,omitempty"`

	// intermediateCA identifies the cert-manager Certificate representing the
	// intermediate CA this CR manages. Required when role=IntermediateCA.
	// +optional
	IntermediateCA *IntermediateCARef `json:"intermediateCA,omitempty"`
}

// PKIRotationStatus defines the observed state of PKIRotation.
type PKIRotationStatus struct {
	// conditions reflect granular sub-state for each phase gate.
	// +listType=map
	// +listMapKey=type
	// +patchStrategy=merge
	// +patchMergeKey=type
	// +optional
	Conditions []metav1.Condition `json:"conditions,omitempty" patchStrategy:"merge" patchMergeKey:"type" protobuf:"bytes,1,rep,name=conditions"` //nolint:lll // kubebuilder-generated struct tag; one line by construction

	// phase is the current state of the rotation state machine.
	// +optional
	Phase PKIRotationPhase `json:"phase,omitempty"`

	// currentSKID is the Subject Key Identifier of the CA certificate
	// currently present in the staging ConfigMap (post-rotation value once Complete).
	// +optional
	CurrentSKID string `json:"currentSKID,omitempty"`

	// previousSKID is the Subject Key Identifier of the CA certificate
	// that was active when the rotation began. Cleared when rotation completes.
	// +optional
	PreviousSKID string `json:"previousSKID,omitempty"`

	// rotationStartedAt records when the current rotation cycle began.
	// +optional
	RotationStartedAt *metav1.Time `json:"rotationStartedAt,omitempty"`

	// lastTransitionTime records when the phase last changed.
	// +optional
	LastTransitionTime *metav1.Time `json:"lastTransitionTime,omitempty"`

	// dualTrustActiveAt records when the operator entered the DualTrustActive phase.
	// Cleared when rotation completes.
	// +optional
	DualTrustActiveAt *metav1.Time `json:"dualTrustActiveAt,omitempty"`
}

// +kubebuilder:object:root=true
// +kubebuilder:subresource:status
// +kubebuilder:resource:scope=Cluster,shortName=pkir
// +kubebuilder:printcolumn:name="Phase",type=string,JSONPath=`.status.phase`
// +kubebuilder:printcolumn:name="Current SKID",type=string,JSONPath=`.status.currentSKID`
// +kubebuilder:printcolumn:name="Age",type=date,JSONPath=`.metadata.creationTimestamp`

// PKIRotation manages the safe rotation of a root CA certificate within a
// cert-manager + trust-manager PKI hierarchy. It implements a dual-trust
// window state machine that ensures the old root CA remains trusted until
// all intermediate CAs have been re-issued against the new root.
type PKIRotation struct {
	metav1.TypeMeta `json:",inline"`

	// metadata is standard object metadata.
	// +optional
	metav1.ObjectMeta `json:"metadata,omitzero"`

	// spec defines the root CA and trust bundle to manage.
	// +required
	Spec PKIRotationSpec `json:"spec,omitzero"`

	// status reflects the observed rotation state.
	// +optional
	Status PKIRotationStatus `json:"status,omitzero"`
}

// +kubebuilder:object:root=true

// PKIRotationList contains a list of PKIRotation.
type PKIRotationList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitzero"`
	Items           []PKIRotation `json:"items"`
}

func init() {
	SchemeBuilder.Register(&PKIRotation{}, &PKIRotationList{})
}
