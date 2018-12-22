package certutil

import (
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
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
	hasher := sha256.New()
	hasher.Write(cert.Raw)
	cert.Fingerprint = base64.StdEncoding.EncodeToString(hasher.Sum([]byte{}))
	return cert, nil
}
