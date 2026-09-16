package pki

import (
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"strings"
)

// SKIDFromPEM parses the first certificate in a PEM block and returns its
// Subject Key Identifier as a colon-separated uppercase hex string (e.g. "01:02:03:04").
// Returns an error if the PEM cannot be decoded, the certificate cannot be parsed,
// or the certificate has no SubjectKeyId extension.
func SKIDFromPEM(certPEM []byte) (string, error) {
	cert, err := parseCert(certPEM)
	if err != nil {
		return "", err
	}
	if len(cert.SubjectKeyId) == 0 {
		return "", fmt.Errorf("certificate has no SubjectKeyId")
	}
	return formatKeyID(cert.SubjectKeyId), nil
}

// AKIDFromPEM parses the first certificate in a PEM block and returns its
// Authority Key Identifier as a colon-separated uppercase hex string.
// Returns an empty string (no error) if the certificate has no AKID.
func AKIDFromPEM(certPEM []byte) (string, error) {
	cert, err := parseCert(certPEM)
	if err != nil {
		return "", err
	}
	return formatKeyID(cert.AuthorityKeyId), nil
}

func parseCert(certPEM []byte) (*x509.Certificate, error) {
	// pem.Decode returns only the first block; rest is intentionally ignored
	// because callers pass single-cert PEM (tls.crt from cert-manager Secrets).
	block, _ := pem.Decode(certPEM)
	if block == nil {
		return nil, fmt.Errorf("failed to decode PEM block")
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("parsing certificate: %w", err)
	}
	return cert, nil
}

func formatKeyID(id []byte) string {
	if len(id) == 0 {
		return ""
	}
	parts := make([]string, len(id))
	for i, b := range id {
		parts[i] = fmt.Sprintf("%02X", b)
	}
	return strings.Join(parts, ":")
}
