package ocsp

import (
	"bytes"
	"crypto/x509"
	"golang.org/x/crypto/ocsp"
	"io/ioutil"
	"log"
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
//	revoked     [1]     IMPLICIT RevokedInfo,
//	unknown     [2]     IMPLICIT UnknownInfo }

type Response int

const (
	Good Response = iota
	Revoked
	Unkown
)

func (r Response) String() string {
	switch r {
	case Good:
		return "good"
	case Revoked:
		return "revoked"
	case Unkown:
		return "unknown"
	default:
		log.Panicf("unknown ocsp response, %d\n", r)
	}
	return ""
}

var responseMap = map[int]Response{
	ocsp.Good:    Good,
	ocsp.Revoked: Revoked,
	ocsp.Unknown: Unkown,
}

func Query(cert, issuer *x509.Certificate) []Response {
	responses := make([]Response, len(cert.OCSPServer))
	if cert.IsCA {
		return responses
	}
	for i, responder := range cert.OCSPServer {
		responses[i] = queryResponder(cert, issuer, responder)
	}
	return responses
}

const OCSPContentType = "application/ocsp-request"

func queryResponder(cert, issuer *x509.Certificate, responder string) Response {
	req, err := ocsp.CreateRequest(cert, issuer, nil)
	if err != nil {
		log.Panic(err)
	}
	ret, err := http.Post(responder, OCSPContentType, bytes.NewReader(req))
	if err != nil {
		log.Panic(err)
	}
	defer ret.Body.Close()
	httpResp, err := ioutil.ReadAll(ret.Body)
	if err != nil {
		log.Panic(err)
	}
	ocspResponse, err := ocsp.ParseResponse(httpResp, issuer)
	if err != nil {
		log.Panic(err)
	}
	return responseMap[ocspResponse.Status]
}

//func TestOCSP(t *testing.T) {
//	var certs []*Certificate
//	for _, c := range entrustChain {
//		cert := parseCertificate(c, t)
//		certs = append(certs, cert)
//		t.Log(cert.OCSPServer, cert.Subject.CommonName)
//	}
//	leaf := certs[0]
//	req, err := ocsp.CreateRequest(leaf.Certificate, certs[1].Certificate, nil)
//	if err != nil {
//		t.Fatal(err)
//	}
//	responder := leaf.OCSPServer[0]
//	t.Log(responder)
//	//encoded := make([]byte, base64.URLEncoding.EncodedLen(len(req)))
//	//base64.URLEncoding.Encode(encoded, req)
//	ret, err := http.Post(responder, "application/ocsp-request", bytes.NewReader(req))
//	if err != nil {
//		t.Fatal(err)
//	}
//	defer ret.Body.Close()
//	t.Log(ret.Request.URL)
//	b, err := ioutil.ReadAll(ret.Body)
//	if err != nil {
//		t.Fatal(err)
//	}
//	resp, err := ocsp.ParseResponse(b, certs[1].Certificate)
//	if err != nil {
//		t.Fatal(err)
//	}
//
//	t.Log(resp.Status == ocsp.Good)
//}
