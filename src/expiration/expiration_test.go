package expiration

import (
	"bytes"
	"crypto/x509"
	"encoding/pem"
	"github.com/christopher-henderson/CACop/expiration/certutil"
	"io/ioutil"
	"log"
	"os"
	"testing"
)

//var revoked = `/Users/chris/Documents/Contracting/mozilla/CACop/src/testdata/data/AffirmTrust Premium/revoked`

const DIST = "/Users/chris/Documents/Contracting/mozilla/testWebSites/dist/Debug"

func init() {
	if err := certutil.Init(DIST); err != nil {
		log.Panic(err)
	}
}

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

func TestUnknownIssuer(t *testing.T) {
	chain := parseChain(revoked)
	c, err := certutil.NewCertutil()
	if err != nil {
		t.Fatal(err)
	}
	defer c.Delete()
	c.Install(chain[0])
	o, err := c.Verify(chain[0])
	t.Log(string(o))
	t.Log(err)
}

var expired = "/Users/chris/Documents/Contracting/mozilla/CACop/src/testdata/data/DST Root CA X3/expired"
var revoked = "/Users/chris/Documents/Contracting/mozilla/CACop/src/testdata/data/DST Root CA X3/revoked"
var valid = "/Users/chris/Documents/Contracting/mozilla/CACop/src/testdata/data/DST Root CA X3/valid"

func TestVerifyChain(t *testing.T) {
	t.Log(VerifyChain(parseChain(valid)))
	t.Log(VerifyChain(parseChain(revoked)))
	t.Log(VerifyChain(parseChain(expired)))
}
