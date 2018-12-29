package certutil

import (
	"crypto"
	"crypto/x509"
	"encoding/pem"
	"fmt"
)

type Fingerprint = string

type Certificate struct {
	*x509.Certificate
	Fingerprint
}

func NewCertificate(encodedPEM []byte) (*Certificate, error) {
	cert := new(Certificate)
	block, _ := pem.Decode(encodedPEM)
	x509cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return cert, err
	}
	cert.Certificate = x509cert
	cert.Fingerprint = FingerprintOf(cert)
	return cert, nil
}

func FingerprintOf(cert *Certificate) Fingerprint {
	hasher := crypto.SHA256.New()
	hasher.Write(cert.Raw)
	return fmt.Sprintf("%x", hasher.Sum(nil))
}
