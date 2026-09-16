// Package pki holds the certificate and PEM primitives the reconcilers build on:
// PEM bundle assembly and pruning, and X.509 subject/authority key identifier
// extraction. It performs no Kubernetes I/O.
package pki

import (
	"bytes"
	"crypto/x509"
	"encoding/pem"
	"fmt"
)

// AppendPEM appends newCert to existing PEM data. If a certificate with the
// same DER content is already present in existing, returns existing unchanged
// (idempotent). Uses DER comparison to avoid false negatives from trailing-
// newline variance across serialization boundaries.
func AppendPEM(existing, newCert []byte) []byte {
	newBlock, _ := pem.Decode(newCert)
	if newBlock != nil {
		rest := existing
		for {
			var b *pem.Block
			b, rest = pem.Decode(rest)
			if b == nil {
				break
			}
			if bytes.Equal(b.Bytes, newBlock.Bytes) {
				return existing
			}
		}
	}
	if len(existing) > 0 && !bytes.HasSuffix(existing, []byte("\n")) {
		existing = append(existing, '\n')
	}
	return append(existing, newCert...)
}

// RemovePEMBySKID parses pemData as a sequence of PEM certificate blocks and
// returns a new PEM concatenation with the first certificate whose SubjectKeyId
// matches targetSKID removed. Blocks that cannot be parsed as certificates
// are retained unchanged. Returns pemData unchanged if no block matches targetSKID.
// Returns an error only if there are non-PEM trailing bytes.
func RemovePEMBySKID(pemData []byte, targetSKID string) ([]byte, error) {
	var result []byte
	rest := pemData
	removed := false
	for {
		var block *pem.Block
		block, rest = pem.Decode(rest)
		if block == nil {
			break
		}
		cert, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			// Retain unparseable blocks unchanged.
			result = append(result, pem.EncodeToMemory(block)...)
			continue
		}
		if !removed && formatKeyID(cert.SubjectKeyId) == targetSKID {
			removed = true
			continue // drop only the first matching block
		}
		result = append(result, pem.EncodeToMemory(block)...)
	}
	if len(bytes.TrimSpace(rest)) > 0 {
		return nil, fmt.Errorf("trailing non-PEM data in input (%d bytes)", len(rest))
	}
	return result, nil
}
