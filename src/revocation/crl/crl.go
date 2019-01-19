package crl

import (
	"crypto/x509"
	"github.com/pkg/errors"
	"io/ioutil"
	"math/big"
	"net/http"
)

type CRL struct {
	Endpoint string
	Revoked  bool
	Error    error
}

func VerifyChain(chain []*x509.Certificate) [][]CRL {
	crls := make([][]CRL, len(chain))
	for i, cert := range chain {
		crls[i] = queryCRLs(cert)
	}
	return crls
}

func queryCRLs(certificate *x509.Certificate) []CRL {
	statuses := make([]CRL, len(certificate.CRLDistributionPoints))
	for i, url := range certificate.CRLDistributionPoints {
		statuses[i] = newCRL(certificate.SerialNumber, url)
	}
	return statuses
}

func newCRL(serialNumber *big.Int, distributionPoint string) (crl CRL) {
	raw, err := http.Get(distributionPoint)
	crl.Endpoint = distributionPoint
	if err != nil {
		crl.Error = errors.Wrapf(err, "failed to retrieve CRL from distribution point %v", distributionPoint)
		return
	}
	defer raw.Body.Close()
	b, err := ioutil.ReadAll(raw.Body)
	if err != nil {
		crl.Error = errors.Wrapf(err, "failed to read response from CRL distribution point %v", distributionPoint)
	}
	c, err := x509.ParseCRL(b)
	if err != nil {
		crl.Error = errors.Wrapf(err, "failed to parse provided CRL\n%v", raw)
		return
	}
	if c.TBSCertList.RevokedCertificates == nil {
		crl.Revoked = false
		return
	}
	for _, revoked := range c.TBSCertList.RevokedCertificates {
		if revoked.SerialNumber.Cmp(serialNumber) == 0 {
			crl.Revoked = true
			break
		}
	}
	return
}
