package expiration

import (
	"crypto/x509"
	"github.com/christopher-henderson/CACop/expiration/certutil"
	"github.com/pkg/errors"
)

type ExpirationStatus struct {
	Valid         bool
	Expired       bool
	IssuerUnknown bool
	Raw           string
	Error         error
}

func VerifyChain(chain []*x509.Certificate) ([]ExpirationStatus, error) {
	statuses := make([]ExpirationStatus, len(chain))
	c, err := certutil.NewCertutil()
	if err != nil {
		return statuses, errors.Wrap(err, "failed to initialize a new NSS certificate database")
	}
	defer c.Delete()
	for _, cert := range chain {
		out, err := c.Install(cert)
		o := string(out)
		if err != nil {
			return statuses, errors.Wrapf(err, "failed to install certificate, %v", o)
		}
	}
	for i, cert := range chain {
		statuses[i] = queryExpiration(cert, c)
	}
	return statuses, nil
}

func queryExpiration(certificate *x509.Certificate, c certutil.Certutil) (exps ExpirationStatus) {
	// @TODO try to figure certutil's error codes. It uses non zero codes when the answer is
	// anything other than just "valid", so it's not a reliable way to know whether or not
	// the tool was fundamentally used wrong or if the cert is just expired or what.
	resp, _ := c.Verify(certificate)
	response := string(resp)
	exps.Raw = response
	exps.Valid = certutil.VALID == response
	exps.Expired = certutil.EXPIRED == response
	exps.IssuerUnknown = certutil.ISSUER_UNKOWN == response
	if !exps.Valid && !exps.Expired && !exps.IssuerUnknown {
		exps.Error = errors.New(string(response))
	}
	return
}
