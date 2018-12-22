package main // import "github.com/christopher-henderson/CACop"

import (
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"

	"github.com/christopher-henderson/CACop/certutil"

	"github.com/mozilla/OneCRL-Tools/certdataDiffCCADB"
)

type Result struct {
	Results []string `json:"result"`
}

func handler(resp http.ResponseWriter, req *http.Request) {
	defer req.Body.Close()
	s, ok := req.URL.Query()["subject"]
	if !ok {
		resp.WriteHeader(400)
		resp.Write([]byte("'subject' query parameter is required\n"))
		return
	}
	subject := s[0]
	caCertRaw, err := ioutil.ReadAll(req.Body)
	if err != nil {
		resp.WriteHeader(400)
		resp.Write([]byte("Error reading body: " + string(caCertRaw)))
		return
	}
	// @TODO validate provided CA cert
	req.Body.Close()
	caCert, err := parseX509(caCertRaw)
	if err != nil {
		resp.WriteHeader(400)
		resp.Write([]byte("Bad PEM: " + err.Error()))
		return
	}
	chain, err := gatherCertificates(string(subject))
	if err != nil {
		resp.WriteHeader(400)
		resp.Write([]byte("Could not retrieve certificate chain from " + string(subject) + " because of " + err.Error()))
		return
	}
	chain = append(chain, caCert)
	c, err := certutil.NewCertutil()
	if err != nil {
		resp.WriteHeader(500)
		fmt.Fprintln(resp, err.Error())
	}
	for _, cert := range chain {
		_, err := c.Install(cert)
		if err != nil {
			resp.Write([]byte(err.Error() + "\n"))
			continue
		}
		answer, err := c.Verify(cert)
		if err != nil {
			fmt.Fprintln(resp, string(answer)+" "+cert.Subject.String())
			continue
		}
		fmt.Fprintln(resp, string(answer))
	}
}

func gatherCertificates(subjectURL string) ([]*x509.Certificate, error) {
	resp, err := http.DefaultClient.Get(subjectURL)
	if err != nil {
		return []*x509.Certificate{}, err
	}
	return resp.TLS.PeerCertificates, err
}

func parseX509(cert []byte) (*x509.Certificate, error) {
	cert = []byte(certdataDiffCCADB.NormalizePEM(string(cert)))
	block, _ := pem.Decode(cert)
	return x509.ParseCertificate(block.Bytes)
}

const DB = "/Users/chris/Documents/Contracting/mozilla/testWebSites/testdb"

// @TODO I can't seem to get this to fail intentionally, be careful
const DIST = "/Users/chris/Documents/Contracting/mozilla/testWebSites/dist/Debug"

func main() {
	log.SetFlags(log.LstdFlags | log.Lshortfile)
	err := certutil.Init(DB, DIST)
	if err != nil {
		log.Panicln(err)
	}
	http.HandleFunc("/", handler)
	if err := http.ListenAndServe("0.0.0.0:8080", nil); err != nil {
		log.Panicln(err)
	}
}
