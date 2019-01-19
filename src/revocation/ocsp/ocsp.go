package ocsp

import (
	"bytes"
	"crypto/x509"
	"github.com/pkg/errors"
	"golang.org/x/crypto/ocsp"
	"io/ioutil"
	"net/http"
)

// RFC 6960
//
// Appendix A. OCSP over HTTP
//
// A.1.  Request
//
// HTTP-based OCSP requests can use either the GET or the POST method to
// submit their requests.  To enable HTTP caching, small requests (that
// after encoding are less than 255 bytes) MAY be submitted using GET.
// If HTTP caching is not important or if the request is greater than
// 255 bytes, the request SHOULD be submitted using POST.  Where privacy
// is a requirement, OCSP transactions exchanged using HTTP MAY be
// protected using either Transport Layer Security/Secure Socket Layer
// (TLS/SSL) or some other lower-layer protocol.
//
// An OCSP request using the GET method is constructed as follows:
//
// GET {url}/{url-encoding of base-64 encoding of the DER encoding of
// the OCSPRequest}
//
// where {url} may be derived from the value of the authority
// information access extension in the certificate being checked for
// revocation, or other local configuration of the OCSP client.
//
// An OCSP request using the POST method is constructed as follows: The
// Content-Type header has the value "application/ocsp-request", while
// the body of the message is the binary value of the DER encoding of
// the OCSPRequest.

// 4.2.1.  ASN.1 Specification of the OCSP Response
//
//
// CertStatus ::= CHOICE {
//	good        [0]     IMPLICIT NULL,
//	expired     [1]     IMPLICIT RevokedInfo,
//	unknown     [2]     IMPLICIT UnknownInfo }

type OCSP struct {
	Responder string
	Good      bool
	Revoked   bool
	Unknown   bool
	Error     error
}

const OCSPContentType = "application/ocsp-request"

func VerifyChain(chain []*x509.Certificate) [][]OCSP {
	ocsps := make([][]OCSP, len(chain))
	if len(chain) == 1 {
		return ocsps
	}
	for i, cert := range chain[:len(chain)-1] {
		ocsps[i] = queryOCSP(cert, chain[i+1])
	}
	ocsps[len(ocsps)-1] = make([]OCSP, 0)
	return ocsps
}

func queryOCSP(certificate, issuer *x509.Certificate) []OCSP {
	responses := make([]OCSP, len(certificate.OCSPServer))
	for i, responder := range certificate.OCSPServer {
		responses[i] = newOCSPResponse(certificate, issuer, responder)
	}
	return responses
}

func newOCSPResponse(certificate, issuer *x509.Certificate, responder string) (response OCSP) {
	response.Responder = responder
	req, err := ocsp.CreateRequest(certificate, issuer, nil)
	if err != nil {
		response.Error = errors.Wrap(err, "failed to create DER encoded OCSP request")
		return
	}
	ret, err := http.Post(responder, OCSPContentType, bytes.NewReader(req))
	if err != nil {
		response.Error = errors.Wrapf(err, "failed to retrieve HTTP POST response from %v", responder)
		return
	}
	defer ret.Body.Close()
	httpResp, err := ioutil.ReadAll(ret.Body)
	if err != nil {
		response.Error = errors.Wrap(err, "failed to read the body of the OCSP response")
		return
	}
	serverResponse, err := ocsp.ParseResponse(httpResp, issuer)
	if err != nil {
		response.Error = errors.Wrapf(err, "failed to parse the OCSP response")
		return
	}
	response.Good = serverResponse.Status == ocsp.Good
	response.Revoked = serverResponse.Status == ocsp.Revoked
	response.Unknown = serverResponse.Status == ocsp.Unknown
	return
}
