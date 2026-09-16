package pki_test

import (
	"bytes"
	"testing"

	"github.com/adaptive-enforcement-lab/private-pki-operator/ci/private-pki-operator/internal/pki"
)

func TestAppendPEM_AddsNewCert(t *testing.T) {
	rootPEM, _ := makeCA(t)
	newRootPEM, _ := makeCA(t)

	result := pki.AppendPEM(rootPEM, newRootPEM)

	if !bytes.Contains(result, rootPEM) {
		t.Error("result missing original root PEM")
	}
	if !bytes.Contains(result, newRootPEM) {
		t.Error("result missing new root PEM")
	}
}

func TestAppendPEM_Idempotent(t *testing.T) {
	rootPEM, _ := makeCA(t)

	once := pki.AppendPEM(rootPEM, rootPEM)
	twice := pki.AppendPEM(once, rootPEM)

	if !bytes.Equal(once, twice) {
		t.Error("AppendPEM should be idempotent when cert already present")
	}
}

func TestRemovePEMBySKID_RemovesMatchingCert(t *testing.T) {
	rootPEM := makeCAWithSKID(t, []byte{0x01, 0x02, 0x03, 0x04})
	newRootPEM := makeCAWithSKID(t, []byte{0x05, 0x06, 0x07, 0x08})

	combined := pki.AppendPEM(rootPEM, newRootPEM)

	oldSKID, err := pki.SKIDFromPEM(rootPEM)
	if err != nil {
		t.Fatalf("SKIDFromPEM: %v", err)
	}

	result, err := pki.RemovePEMBySKID(combined, oldSKID)
	if err != nil {
		t.Fatalf("RemovePEMBySKID: %v", err)
	}

	if bytes.Contains(result, rootPEM) {
		t.Error("old root PEM should have been removed")
	}
	if !bytes.Contains(result, newRootPEM) {
		t.Error("new root PEM should still be present")
	}
}

func TestRemovePEMBySKID_NoMatch_ReturnsUnchanged(t *testing.T) {
	rootPEM, _ := makeCA(t)

	result, err := pki.RemovePEMBySKID(rootPEM, "FF:FF:FF:FF")
	if err != nil {
		t.Fatalf("RemovePEMBySKID: %v", err)
	}
	if !bytes.Equal(result, rootPEM) {
		t.Error("unmatched removal should return unchanged PEM data")
	}
}
