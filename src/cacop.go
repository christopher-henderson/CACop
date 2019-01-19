package main // import "github.com/christopher-henderson/CACop"

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"github.com/christopher-henderson/CACop/expiration"
	"github.com/christopher-henderson/CACop/model"
	"github.com/christopher-henderson/CACop/revocation/crl"
	"github.com/christopher-henderson/CACop/revocation/ocsp"
	"io/ioutil"
	"log"
	"net/http"
	"regexp"

	"github.com/christopher-henderson/CACop/validation/certutil"
)

func verifyCertificateChain(resp http.ResponseWriter, req *http.Request) {
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
	req.Body.Close()
	cert := NormalizePEM(caCertRaw)
	block, rest := pem.Decode(cert)
	if len(rest) != 0 {
		log.Println("got trailing certificate data for the provided CA")
		log.Println(string(rest))
	}
	caCert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		resp.WriteHeader(400)
		resp.Write([]byte("Bad PEM: " + err.Error()))
		return
	}
	chain, err := GatherCertificateChain(string(subject))
	if err != nil {
		resp.WriteHeader(400)
		resp.Write([]byte("Could not retrieve certificate chain from " + string(subject) + " because of " + err.Error()))
		return
	}
	switch chain[len(chain)-1].IsCA {
	case true:
		// If the subject website is offering a CA certificate in its chain
		// then ignore and replace it with the CA provided by the request.
		chain[len(chain)-1] = caCert
	case false:
		// Otherwise, it appears that the subject website has only offered
		// its leaf and intermediates, thus we can just tack on the target CA.
		chain = append(chain, caCert)
	}
	result := model.TestWebsiteResult{}
	result.SubjectURL = subject
	result.Chain = VerifyChain(chain)
	result.Error = nil
	encoder := json.NewEncoder(resp)
	encoder.SetIndent("", "    ")
	err = encoder.Encode(result)
	if err != nil {
		resp.WriteHeader(500)
		fmt.Fprintf(resp, "internal error: %s", err)
	}
	//results := make([]*model.CertificateResultOld, len(chain))
	//for i, cert := range chain {
	//	results[i] = model.NewCertificateResult(cert)
	//}
	//validation.Verify(results)
	//encoder := json.NewEncoder(resp)
	//encoder.SetIndent("", "    ")
	//err = encoder.Encode(results)
	//if err != nil {
	//	resp.WriteHeader(500)
	//	fmt.Fprintf(resp, "internal error: %s", err)
	//}
}

func verifyCertificateChainNoCA(resp http.ResponseWriter, req *http.Request) {
	defer req.Body.Close()
	s, ok := req.URL.Query()["subject"]
	if !ok {
		resp.WriteHeader(400)
		resp.Write([]byte("'subject' query parameter is required\n"))
		return
	}
	subject := s[0]
	chain, err := GatherCertificateChain(string(subject))
	if err != nil {
		resp.WriteHeader(400)
		resp.Write([]byte("Could not retrieve certificate chain from " + string(subject) + " because of " + err.Error()))
		return
	}
	result := model.TestWebsiteResult{}
	result.SubjectURL = subject
	result.Chain = VerifyChain(chain)
	result.Error = nil
	encoder := json.NewEncoder(resp)
	encoder.SetIndent("", "    ")
	err = encoder.Encode(result)
	if err != nil {
		resp.WriteHeader(500)
		fmt.Fprintf(resp, "internal error: %s", err)
	}
}

func VerifyChain(chain []*x509.Certificate) model.ChainResult {
	result := model.ChainResult{}
	expirations, err := expiration.VerifyChain(chain)
	if err != nil {
		log.Panicln(err)
	}
	ocsps := ocsp.VerifyChain(chain)
	crls := crl.VerifyChain(chain)
	result.Leaf = model.NewCeritifcateResult(chain[0], ocsps[0], crls[0], expirations[0])
	result.Intermediates = make([]model.CertificateResult, len(chain[1:len(chain)-1]))
	log.Println(chain)
	log.Println(len(chain) - 1)
	log.Println(len(ocsps))
	log.Println(len(crls))
	for i := 1; i < len(chain)-1; i++ {
		result.Intermediates[i-1] = model.NewCeritifcateResult(chain[i], ocsps[i], crls[i], expirations[i])
	}
	ca := len(chain) - 1
	result.Root = model.NewCeritifcateResult(chain[ca], ocsps[ca], crls[ca], expirations[ca])
	return result
}

func GatherCertificateChain(subjectURL string) ([]*x509.Certificate, error) {
	resp, err := http.DefaultClient.Get(subjectURL)
	if err != nil {
		return []*x509.Certificate{}, err
	}
	return resp.TLS.PeerCertificates, err
}

var pemStripper = regexp.MustCompile(`('|\n|-----BEGIN CERTIFICATE-----|-----END CERTIFICATE-----)`)

// normalizePEM ignores any formatting or string artifacts that the PEM may have had
// and applies https://tools.ietf.org/html/rfc1421
func NormalizePEM(pem []byte) (fmtedPEM []byte) {
	if len(pem) == 0 {
		return
	}
	pem = pemStripper.ReplaceAll(pem, []byte{})
	fmtedPEM = append(fmtedPEM, "-----BEGIN CERTIFICATE-----\n"...)
	width := 64 // Columns per line https://tools.ietf.org/html/rfc1421
	for len(pem) > 0 {
		if len(pem) < width {
			width = len(pem)
		}
		fmtedPEM = append(fmtedPEM, pem[:width]...)
		fmtedPEM = append(fmtedPEM, '\n')
		pem = pem[width:]
	}
	return append(fmtedPEM, "-----END CERTIFICATE-----"...)
}

const DB = "/Users/chris/Documents/Contracting/mozilla/testWebSites/testdb"

// @TODO I can't seem to get this to fail intentionally, be careful
const DIST = "/Users/chris/Documents/Contracting/mozilla/testWebSites/dist/Debug"

func main() {
	log.SetFlags(log.LstdFlags | log.Lshortfile)
	// Very mandatory otherwise the HTTP package will vomit on revoked/expired certificates and return an error.
	http.DefaultTransport.(*http.Transport).TLSClientConfig = &tls.Config{InsecureSkipVerify: true}
	err := certutil.Init(DIST)
	if err != nil {
		log.Panicln(err)
	}
	http.HandleFunc("/", verifyCertificateChain)
	http.HandleFunc("/bundledCA", verifyCertificateChainNoCA)
	if err := http.ListenAndServe("0.0.0.0:8080", nil); err != nil {
		log.Panicln(err)
	}
}
