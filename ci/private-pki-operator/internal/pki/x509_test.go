package pki_test

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/pem"
	"math/big"
	"testing"
	"time"

	"github.com/adaptive-enforcement-lab/private-pki-operator/ci/private-pki-operator/internal/pki"
)

func makeCA(t *testing.T) (certPEM []byte, key *ecdsa.PrivateKey) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "Test Root CA"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		IsCA:         true,
		SubjectKeyId: []byte{0x01, 0x02, 0x03, 0x04},
		// AuthorityKeyId is explicitly nil; Go's x509 library also skips
		// setting it for self-signed certs (same subject==issuer), but we
		// make the intent clear here.
		AuthorityKeyId:        nil,
		KeyUsage:              x509.KeyUsageCertSign,
		BasicConstraintsValid: true,
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("create cert: %v", err)
	}
	certPEM = pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	return certPEM, key
}

// makeCAWithSKID generates a self-signed CA cert with the given SubjectKeyId.
func makeCAWithSKID(t *testing.T, skid []byte) []byte {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	template := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "Test Root CA"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		IsCA:                  true,
		SubjectKeyId:          skid,
		AuthorityKeyId:        nil,
		KeyUsage:              x509.KeyUsageCertSign,
		BasicConstraintsValid: true,
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("create cert: %v", err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
}

func makeIntermediate(t *testing.T, caCertPEM []byte, caKey *ecdsa.PrivateKey) []byte {
	t.Helper()
	block, _ := pem.Decode(caCertPEM)
	caCert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatalf("parse CA cert: %v", err)
	}
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate intermediate key: %v", err)
	}
	template := &x509.Certificate{
		SerialNumber:          big.NewInt(2),
		Subject:               pkix.Name{CommonName: "Test Intermediate CA"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		IsCA:                  true,
		SubjectKeyId:          []byte{0x05, 0x06, 0x07, 0x08},
		KeyUsage:              x509.KeyUsageCertSign,
		BasicConstraintsValid: true,
	}
	der, err := x509.CreateCertificate(rand.Reader, template, caCert, &key.PublicKey, caKey)
	if err != nil {
		t.Fatalf("create intermediate cert: %v", err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
}

func TestSKIDFromPEM(t *testing.T) {
	caCertPEM, _ := makeCA(t)
	skid, err := pki.SKIDFromPEM(caCertPEM)
	if err != nil {
		t.Fatalf("SKIDFromPEM: %v", err)
	}
	if skid != "01:02:03:04" {
		t.Errorf("got SKID %q, want %q", skid, "01:02:03:04")
	}
}

func TestAKIDFromPEM(t *testing.T) {
	caCertPEM, caKey := makeCA(t)
	intermPEM := makeIntermediate(t, caCertPEM, caKey)
	akid, err := pki.AKIDFromPEM(intermPEM)
	if err != nil {
		t.Fatalf("AKIDFromPEM: %v", err)
	}
	if akid != "01:02:03:04" {
		t.Errorf("got AKID %q, want %q", akid, "01:02:03:04")
	}
}

func TestSKIDFromPEM_InvalidPEM(t *testing.T) {
	_, err := pki.SKIDFromPEM([]byte("not a PEM"))
	if err == nil {
		t.Error("expected error for invalid PEM")
	}
}

func TestAKIDFromPEM_NoAKID(t *testing.T) {
	caCertPEM, _ := makeCA(t)
	akid, err := pki.AKIDFromPEM(caCertPEM)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if akid != "" {
		t.Errorf("got AKID %q for self-signed cert, want empty", akid)
	}
}

// makeCANoSKID generates a self-signed X.509 v1 certificate with no extensions,
// so SubjectKeyId is guaranteed absent. Go 1.15+ auto-synthesises SubjectKeyId
// when using x509.CreateCertificate, so we build the DER manually via
// encoding/asn1 to produce a valid v1 cert without the SKID extension.
func makeCANoSKID(t *testing.T) []byte {
	t.Helper()

	// OIDs for ECDSA with SHA-256 and P-256.
	oidEcdsaWithSHA256 := asn1.ObjectIdentifier{1, 2, 840, 10045, 4, 3, 2}

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}

	// Marshal the public key into SubjectPublicKeyInfo DER.
	pubKeyDER, err := x509.MarshalPKIXPublicKey(&key.PublicKey)
	if err != nil {
		t.Fatalf("marshal public key: %v", err)
	}

	// Encode subject/issuer name.
	name := pkix.Name{CommonName: "Test Root CA No SKID"}
	subjectDER, err := asn1.Marshal(name.ToRDNSequence())
	if err != nil {
		t.Fatalf("marshal subject: %v", err)
	}

	// Encode validity.
	type validity struct {
		NotBefore time.Time
		NotAfter  time.Time
	}
	validityDER, err := asn1.Marshal(validity{
		NotBefore: time.Now().Add(-time.Hour),
		NotAfter:  time.Now().Add(time.Hour),
	})
	if err != nil {
		t.Fatalf("marshal validity: %v", err)
	}

	// Build TBSCertificate (v1: no version field, no extensions → no SKID).
	type tbsCertificate struct {
		SerialNumber         *big.Int
		SignatureAlgorithm   pkix.AlgorithmIdentifier
		Issuer               asn1.RawValue
		Validity             asn1.RawValue
		Subject              asn1.RawValue
		SubjectPublicKeyInfo asn1.RawValue
		// No extensions field — SubjectKeyId will be absent.
	}
	tbs := tbsCertificate{
		SerialNumber:         big.NewInt(3),
		SignatureAlgorithm:   pkix.AlgorithmIdentifier{Algorithm: oidEcdsaWithSHA256},
		Issuer:               asn1.RawValue{FullBytes: subjectDER},
		Validity:             asn1.RawValue{FullBytes: validityDER},
		Subject:              asn1.RawValue{FullBytes: subjectDER},
		SubjectPublicKeyInfo: asn1.RawValue{FullBytes: pubKeyDER},
	}
	tbsDER, err := asn1.Marshal(tbs)
	if err != nil {
		t.Fatalf("marshal tbs: %v", err)
	}

	// Sign the TBSCertificate.
	digest := sha256.Sum256(tbsDER)
	sig, err := key.Sign(rand.Reader, digest[:], crypto.SHA256)
	if err != nil {
		t.Fatalf("sign tbs: %v", err)
	}

	// Build the full Certificate SEQUENCE.
	type certificate struct {
		TBSCertificate     asn1.RawValue
		SignatureAlgorithm pkix.AlgorithmIdentifier
		Signature          asn1.BitString
	}
	certDER, err := asn1.Marshal(certificate{
		TBSCertificate:     asn1.RawValue{FullBytes: tbsDER},
		SignatureAlgorithm: pkix.AlgorithmIdentifier{Algorithm: oidEcdsaWithSHA256},
		Signature:          asn1.BitString{Bytes: sig, BitLength: len(sig) * 8},
	})
	if err != nil {
		t.Fatalf("marshal certificate: %v", err)
	}

	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER})
}

func TestSKIDFromPEM_NoSKID(t *testing.T) {
	certPEM := makeCANoSKID(t)
	_, err := pki.SKIDFromPEM(certPEM)
	if err == nil {
		t.Error("expected error when cert has no SubjectKeyId")
	}
}
