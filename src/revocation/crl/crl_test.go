package crl

import (
	"bytes"
	"crypto/x509"
	"encoding/pem"
	"io/ioutil"
	"os"
	"testing"
)

var revoked = `/Users/chris/Documents/Contracting/mozilla/CACop/src/testdata/data/AffirmTrust Premium/revoked`

func parseChain(path string) (certs []*x509.Certificate) {
	f, err := os.Open(path)
	if err != nil {
		panic(err)
	}
	raw, err := ioutil.ReadAll(f)
	if err != nil {
		panic(err)
	}
	for _, b := range bytes.SplitAfter(raw, []byte("-----END CERTIFICATE-----")) {
		block, rest := pem.Decode(b)
		if len(rest) != 0 {
			continue
		}
		cert, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			panic(err)
		}
		certs = append(certs, cert)
	}
	return
}

func TestCRL(t *testing.T) {
	for _, cert := range parseChain(revoked) {
		crl := QueryCRLs(cert)
		t.Log(crl)
	}
}
