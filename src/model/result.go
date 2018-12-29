package model

import (
	"crypto/x509"
	"github.com/christopher-henderson/CACop/revocation/ocsp"
)

type CertificateResult struct {
	Certificate  *x509.Certificate
	CRLStatus    []string
	OCSPResponse []ocsp.Response
	Lint         []string
	Validation   []string
}

func NewCertificateResult(cert *x509.Certificate) *CertificateResult {
	return &CertificateResult{
		Certificate:  cert,
		CRLStatus:    make([]string, 0),
		OCSPResponse: make([]ocsp.Response, 0),
		Lint:         make([]string, 0),
		Validation:   make([]string, 0),
	}
}
