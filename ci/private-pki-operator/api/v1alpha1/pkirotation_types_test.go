package v1alpha1_test

import (
	"testing"

	platformv1alpha1 "github.com/adaptive-enforcement-lab/private-pki-operator/ci/private-pki-operator/api/v1alpha1"
)

func TestPKIRotationRole_Defaults(t *testing.T) {
	spec := platformv1alpha1.PKIRotationSpec{}
	// Role zero value must be empty string (not RootCA) — kubebuilder default handles CRD defaulting.
	// In-process, code must treat "" the same as RootCA.
	if spec.Role != "" && spec.Role != platformv1alpha1.RoleRootCA {
		t.Errorf("unexpected default Role: %s", spec.Role)
	}
}

func TestPKIRotationRole_Values(t *testing.T) {
	if platformv1alpha1.RoleRootCA != "RootCA" {
		t.Error("RoleRootCA must equal 'RootCA'")
	}
	if platformv1alpha1.RoleIntermediateCA != "IntermediateCA" {
		t.Error("RoleIntermediateCA must equal 'IntermediateCA'")
	}
}

func TestIntermediateCARef_Fields(t *testing.T) {
	ref := platformv1alpha1.IntermediateCARef{
		CertificateName:      "private-intermediate-ca",
		CertificateNamespace: "cert-manager",
	}
	if ref.CertificateName == "" || ref.CertificateNamespace == "" {
		t.Error("IntermediateCARef fields must be non-empty when set")
	}
}

func TestPKIRotationStatus_SKIDFields(t *testing.T) {
	s := platformv1alpha1.PKIRotationStatus{}
	s.CurrentSKID = "aa:bb:cc"
	s.PreviousSKID = "11:22:33"
	if s.CurrentSKID != "aa:bb:cc" {
		t.Error("CurrentSKID must be settable")
	}
	if s.PreviousSKID != "11:22:33" {
		t.Error("PreviousSKID must be settable")
	}
}
