package verification

import (
	"crypto/x509"
	"github.com/christopher-henderson/CACop/certutil"
	log "github.com/sirupsen/logrus"
)

type Result struct {
	Cert    *x509.Certificate
	Message string
	Error   error
}

type Results = []Result

func VerifyChain(chain []*x509.Certificate) (Results, error) {
	var results Results
	c, err := certutil.NewCertutil()
	if err != nil {
		return results, err
	}
	defer func() {
		err := c.Delete()
		if err != nil {
			log.Warningf("Failed to cleanup temp dir %s", err)
		}
	}()
	c.Install(chain[0])
	//for _, cert := range chain[1:] {
	//	out, err := c.InstallCA(cert)
	//	if err != nil {
	//		return results, errors.Wrapf(err, "Error from certutil install %s", string(out))
	//	}
	//}
	c.Verify(chain[0])
	//for _, cert := range chain[1:] {
	//	out, err := c.VerifyCA(cert)
	//	if err != nil {
	//		return results, errors.Wrapf(err, "Error from certutil verify %s, %s", string(out), cert.Subject.CommonName)
	//	}
	//}
	return results, nil
}
