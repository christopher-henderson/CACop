package certutil

import (
	"bytes"
	"crypto"
	"github.com/pkg/errors"
	"log"
	"net/http"
	"testing"
)

const DB = "/Users/chris/Documents/Contracting/mozilla/testWebSites/testdb"
const DIST = "/Users/chris/Documents/Contracting/mozilla/testWebSites/dist/Debug"

func init() {
	if err := Init(DB, DIST); err != nil {
		log.Panic(err)
	}
}

var letsencrypt = []byte(`-----BEGIN CERTIFICATE-----
MIIH5jCCBs6gAwIBAgISA1D/hn92MdZxKQOTmA2iFrUHMA0GCSqGSIb3DQEBCwUA
MEoxCzAJBgNVBAYTAlVTMRYwFAYDVQQKEw1MZXQncyBFbmNyeXB0MSMwIQYDVQQD
ExpMZXQncyBFbmNyeXB0IEF1dGhvcml0eSBYMzAeFw0xODEwMDUxODExNTdaFw0x
OTAxMDMxODExNTdaMB4xHDAaBgNVBAMTE3d3dy5sZXRzZW5jcnlwdC5vcmcwggEi
MA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQDTefxpwDYnmn2zqwLHd8csu9HC
c33k9rbIMWkbQcXSTT/j8n6Wkzc4N9dK0AQv99u2y30JzJE9wniXw0eB4obTds15
u88rkbI8F33F+aFtliRgSYjr7XmWPjNpeQUozRBRsnP2Bsskd6NwUM/Y3Aqp7hcp
jA/+s0Zpcvf09G5HFaWPhG+pZLPS+F5mN+6Zu/h3xH/QF8SGXmhLVk5FgGcZrEto
FJZP6sJLo3wSQjS1ZC68CpAtXla1zA1R9nDFf0GMiAxzase/urBPa5uaGTi9nyGc
gh+OIYGODfOd7ox48iaA/QMTZkCr/2tyPGN6ZT3Ac6JyTBvlbiHkJqrQImAJAgMB
AAGjggTwMIIE7DAOBgNVHQ8BAf8EBAMCBaAwHQYDVR0lBBYwFAYIKwYBBQUHAwEG
CCsGAQUFBwMCMAwGA1UdEwEB/wQCMAAwHQYDVR0OBBYEFBn3p/3O4C1DQdui8FEX
NiyF/EhSMB8GA1UdIwQYMBaAFKhKamMEfd265tE5t6ZFZe/zqOyhMG8GCCsGAQUF
BwEBBGMwYTAuBggrBgEFBQcwAYYiaHR0cDovL29jc3AuaW50LXgzLmxldHNlbmNy
eXB0Lm9yZzAvBggrBgEFBQcwAoYjaHR0cDovL2NlcnQuaW50LXgzLmxldHNlbmNy
eXB0Lm9yZy8wggHxBgNVHREEggHoMIIB5IIbY2VydC5pbnQteDEubGV0c2VuY3J5
cHQub3JnghtjZXJ0LmludC14Mi5sZXRzZW5jcnlwdC5vcmeCG2NlcnQuaW50LXgz
LmxldHNlbmNyeXB0Lm9yZ4IbY2VydC5pbnQteDQubGV0c2VuY3J5cHQub3Jnghxj
ZXJ0LnJvb3QteDEubGV0c2VuY3J5cHQub3Jngh9jZXJ0LnN0YWdpbmcteDEubGV0
c2VuY3J5cHQub3Jngh9jZXJ0LnN0Zy1pbnQteDEubGV0c2VuY3J5cHQub3JngiBj
ZXJ0LnN0Zy1yb290LXgxLmxldHNlbmNyeXB0Lm9yZ4ISY3AubGV0c2VuY3J5cHQu
b3JnghpjcC5yb290LXgxLmxldHNlbmNyeXB0Lm9yZ4ITY3BzLmxldHNlbmNyeXB0
Lm9yZ4IbY3BzLnJvb3QteDEubGV0c2VuY3J5cHQub3Jnghtjcmwucm9vdC14MS5s
ZXRzZW5jcnlwdC5vcmeCD2xldHNlbmNyeXB0Lm9yZ4IWb3JpZ2luLmxldHNlbmNy
eXB0Lm9yZ4IXb3JpZ2luMi5sZXRzZW5jcnlwdC5vcmeCFnN0YXR1cy5sZXRzZW5j
cnlwdC5vcmeCE3d3dy5sZXRzZW5jcnlwdC5vcmcwgf4GA1UdIASB9jCB8zAIBgZn
gQwBAgEwgeYGCysGAQQBgt8TAQEBMIHWMCYGCCsGAQUFBwIBFhpodHRwOi8vY3Bz
LmxldHNlbmNyeXB0Lm9yZzCBqwYIKwYBBQUHAgIwgZ4MgZtUaGlzIENlcnRpZmlj
YXRlIG1heSBvbmx5IGJlIHJlbGllZCB1cG9uIGJ5IFJlbHlpbmcgUGFydGllcyBh
bmQgb25seSBpbiBhY2NvcmRhbmNlIHdpdGggdGhlIENlcnRpZmljYXRlIFBvbGlj
eSBmb3VuZCBhdCBodHRwczovL2xldHNlbmNyeXB0Lm9yZy9yZXBvc2l0b3J5LzCC
AQQGCisGAQQB1nkCBAIEgfUEgfIA8AB2AG9Tdqwx8DEZ2JkApFEV/3cVHBHZAsEA
KQaNsgiaN9kTAAABZkWkxE0AAAQDAEcwRQIhAOOzwbkufRWHlbBjEX5nfXo6E+s/
N8gf3KMikZPrTG/FAiBuMalnDo6pgwMIEZxYa2KyDohLoqo6lPA28/klsecEvAB2
AGPy283oO8wszwtyhCdXazOkjWF3j711pjixx2hUS9iNAAABZkWkw4IAAAQDAEcw
RQIhAOS09dkvx+SPg4maZ9niWCWzeF9H3SSnSF0Q1zH8mdTZAiBvYic/XxvMAShT
XfSc0/EtLg5Sft1D4667DAT7mQgu0jANBgkqhkiG9w0BAQsFAAOCAQEAeHiwK8y1
PhKU+fkiVEOrt3pj4vQlw7NhIyBnc/IEm/aC+Bx8p1cCifoiFSnV138lMe+oKToS
jmRNGZuXqr0Rg5Igwe0H/wbc2GmDaW1qSvfJ+7UjfJUHmNWxX5Nm/iFZ/HCDqWSG
lXbLgLyAYoD2VJKgLtrlnSOgQH2lp/z/CUxam1hk5aG7GUpau/dYphdUdMSchS+A
B8ktad7hW6c9C6dDuSK53raN5p501s3snTy7MbchO14xvfqn7E6DCEDnqwUuqaCz
sLjyuvFWMn7YytIssrlr/cNGUz1q3v3WQ7ZfgR2IuMncorKCrhwfTNq59dciaCHZ
goZ3NpE9UY447g==
-----END CERTIFICATE-----`)

var letsencryptIntermediate = []byte(`-----BEGIN CERTIFICATE-----
MIIEkjCCA3qgAwIBAgIQCgFBQgAAAVOFc2oLheynCDANBgkqhkiG9w0BAQsFADA/
MSQwIgYDVQQKExtEaWdpdGFsIFNpZ25hdHVyZSBUcnVzdCBDby4xFzAVBgNVBAMT
DkRTVCBSb290IENBIFgzMB4XDTE2MDMxNzE2NDA0NloXDTIxMDMxNzE2NDA0Nlow
SjELMAkGA1UEBhMCVVMxFjAUBgNVBAoTDUxldCdzIEVuY3J5cHQxIzAhBgNVBAMT
GkxldCdzIEVuY3J5cHQgQXV0aG9yaXR5IFgzMIIBIjANBgkqhkiG9w0BAQEFAAOC
AQ8AMIIBCgKCAQEAnNMM8FrlLke3cl03g7NoYzDq1zUmGSXhvb418XCSL7e4S0EF
q6meNQhY7LEqxGiHC6PjdeTm86dicbp5gWAf15Gan/PQeGdxyGkOlZHP/uaZ6WA8
SMx+yk13EiSdRxta67nsHjcAHJyse6cF6s5K671B5TaYucv9bTyWaN8jKkKQDIZ0
Z8h/pZq4UmEUEz9l6YKHy9v6Dlb2honzhT+Xhq+w3Brvaw2VFn3EK6BlspkENnWA
a6xK8xuQSXgvopZPKiAlKQTGdMDQMc2PMTiVFrqoM7hD8bEfwzB/onkxEz0tNvjj
/PIzark5McWvxI0NHWQWM6r6hCm21AvA2H3DkwIDAQABo4IBfTCCAXkwEgYDVR0T
AQH/BAgwBgEB/wIBADAOBgNVHQ8BAf8EBAMCAYYwfwYIKwYBBQUHAQEEczBxMDIG
CCsGAQUFBzABhiZodHRwOi8vaXNyZy50cnVzdGlkLm9jc3AuaWRlbnRydXN0LmNv
bTA7BggrBgEFBQcwAoYvaHR0cDovL2FwcHMuaWRlbnRydXN0LmNvbS9yb290cy9k
c3Ryb290Y2F4My5wN2MwHwYDVR0jBBgwFoAUxKexpHsscfrb4UuQdf/EFWCFiRAw
VAYDVR0gBE0wSzAIBgZngQwBAgEwPwYLKwYBBAGC3xMBAQEwMDAuBggrBgEFBQcC
ARYiaHR0cDovL2Nwcy5yb290LXgxLmxldHNlbmNyeXB0Lm9yZzA8BgNVHR8ENTAz
MDGgL6AthitodHRwOi8vY3JsLmlkZW50cnVzdC5jb20vRFNUUk9PVENBWDNDUkwu
Y3JsMB0GA1UdDgQWBBSoSmpjBH3duubRObemRWXv86jsoTANBgkqhkiG9w0BAQsF
AAOCAQEA3TPXEfNjWDjdGBX7CVW+dla5cEilaUcne8IkCJLxWh9KEik3JHRRHGJo
uM2VcGfl96S8TihRzZvoroed6ti6WqEBmtzw3Wodatg+VyOeph4EYpr/1wXKtx8/
wApIvJSwtmVi4MFU5aMqrSDE6ea73Mj2tcMyo5jMd6jmeWUHK8so/joWUoHOUgwu
X4Po1QYz+3dszkDqMp4fklxBwXRsW10KXzPMTZ+sOPAveyxindmjkW8lGy+QsRlG
PfZ+G6Z6h7mjem0Y+iWlkYcV4PIWL1iwBi8saCbGS5jN2p8M+X+Q7UNKEkROb3N6
KOqkqm57TH2H3eDJAkSnh6/DNFu0Qg==
-----END CERTIFICATE-----`)

var letsencryptRoot = []byte(`-----BEGIN CERTIFICATE-----
MIIDSjCCAjKgAwIBAgIQRK+wgNajJ7qJMDmGLvhAazANBgkqhkiG9w0BAQUFADA/
MSQwIgYDVQQKExtEaWdpdGFsIFNpZ25hdHVyZSBUcnVzdCBDby4xFzAVBgNVBAMT
DkRTVCBSb290IENBIFgzMB4XDTAwMDkzMDIxMTIxOVoXDTIxMDkzMDE0MDExNVow
PzEkMCIGA1UEChMbRGlnaXRhbCBTaWduYXR1cmUgVHJ1c3QgQ28uMRcwFQYDVQQD
Ew5EU1QgUm9vdCBDQSBYMzCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEB
AN+v6ZdQCINXtMxiZfaQguzH0yxrMMpb7NnDfcdAwRgUi+DoM3ZJKuM/IUmTrE4O
rz5Iy2Xu/NMhD2XSKtkyj4zl93ewEnu1lcCJo6m67XMuegwGMoOifooUMM0RoOEq
OLl5CjH9UL2AZd+3UWODyOKIYepLYYHsUmu5ouJLGiifSKOeDNoJjj4XLh7dIN9b
xiqKqy69cK3FCxolkHRyxXtqqzTWMIn/5WgTe1QLyNau7Fqckh49ZLOMxt+/yUFw
7BZy1SbsOFU5Q9D8/RhcQPGX69Wam40dutolucbY38EVAjqr2m7xPi71XAicPNaD
aeQQmxkqtilX4+U9m5/wAl0CAwEAAaNCMEAwDwYDVR0TAQH/BAUwAwEB/zAOBgNV
HQ8BAf8EBAMCAQYwHQYDVR0OBBYEFMSnsaR7LHH62+FLkHX/xBVghYkQMA0GCSqG
SIb3DQEBBQUAA4IBAQCjGiybFwBcqR7uKGY3Or+Dxz9LwwmglSBd49lZRNI+DT69
ikugdB/OEIKcdBodfpga3csTS7MgROSR6cz8faXbauX+5v3gTt23ADq1cEmv8uXr
AvHRAosZy5Q6XkjEGB5YGV8eAlrwDPGxrancWYaLbumR9YbK+rlmM6pZW87ipxZz
R8srzJmwN0jP41ZL9c8PDHIyh8bwRLtTcm1D9SZImlJnt1ir/md2cXjbDaJWFBM5
JDGFoqgCWjBH4d1QB7wCCZAA62RjYJsWvIjJEubSfZGL+T0yjWW06XyxV3bqxbYo
Ob8VZRzI9neWagqNdwvYkQsEjgfbKbYK7p2CNTUQ
-----END CERTIFICATE-----`)

var letsencryptChain = [][]byte{letsencrypt, letsencryptIntermediate, letsencryptRoot}

var expiredEnstrust = []byte(`-----BEGIN CERTIFICATE-----
MIIFpjCCBSygAwIBAgIRAL6LReEn8jaqAAAAAFagKQEwCgYIKoZIzj0EAwIwgbox
CzAJBgNVBAYTAlVTMRYwFAYDVQQKEw1FbnRydXN0LCBJbmMuMSgwJgYDVQQLEx9T
ZWUgd3d3LmVudHJ1c3QubmV0L2xlZ2FsLXRlcm1zMTkwNwYDVQQLEzAoYykgMjAx
NiBFbnRydXN0LCBJbmMuIC0gZm9yIGF1dGhvcml6ZWQgdXNlIG9ubHkxLjAsBgNV
BAMTJUVudHJ1c3QgQ2VydGlmaWNhdGlvbiBBdXRob3JpdHkgLSBMMUowHhcNMTcw
NjA2MTM1MTI2WhcNMTcwNjA3MTQyMTE4WjCByDELMAkGA1UEBhMCQ0ExEDAOBgNV
BAgTB09udGFyaW8xDzANBgNVBAcTBkthbmF0YTETMBEGCysGAQQBgjc8AgEDEwJV
UzEWMBQGCysGAQQBgjc8AgECEwVUZXhhczEWMBQGA1UEChMNRW50cnVzdCwgSW5j
LjEdMBsGA1UEDxMUUHJpdmF0ZSBPcmdhbml6YXRpb24xEjAQBgNVBAUTCTExNTg2
ODUwMDEeMBwGA1UEAxMVZXhwaXJlZGVjLmVudHJ1c3QubmV0MFkwEwYHKoZIzj0C
AQYIKoZIzj0DAQcDQgAERxqiqJI9x2VZq86/GIcczmkw9qEFqBjvewc+B9EZHOa+
27CXSaNFL50esl9SOeAHDvYBjQZdOUbLHLm2K5pBc6OCAwEwggL9MCAGA1UdEQQZ
MBeCFWV4cGlyZWRlYy5lbnRydXN0Lm5ldDCCAYEGCisGAQQB1nkCBAIEggFxBIIB
bQFrAHcA7ku9t3XOYLrhQmkfq+GeZqMPfl+wctiDAMR7iXqo/csAAAFcfcgi4gAA
BAMASDBGAiEA43UHIurGfd4GSSRpQy7dRPgB2PWmtkLt17jz4a08r3UCIQDKUnKY
QkWYejTvEe0A7uYK/28rKIq+t/DuVcqr+ft8swB3AFYUBpov18Ls0/XhvUSyPsdG
drm8mRFcwO+UmFXWidDdAAABXH3IJc8AAAQDAEgwRgIhAPeabTr2GM6/oC5laF8X
QYUL+XIPIvw7LJBXETbthi/EAiEAooISlTQsFtI//i7d1rmkcaHyH+mY1CGBJkwN
CrhFIrcAdwCkuQmQtBhYFIe7E6LMZ3AKPDWYBPkb37jjd80OyA3cEAAAAVx9yCbe
AAAEAwBIMEYCIQDBRC6y2kkJjAKrhXk4AOLtjF1x0EtS2M+AOfq+LHtazAIhANE3
StntO7+VjR0tE7b+jU9VwjBxnxASoKOdyTgdOvxdMA4GA1UdDwEB/wQEAwIHgDAT
BgNVHSUEDDAKBggrBgEFBQcDATBjBggrBgEFBQcBAQRXMFUwIwYIKwYBBQUHMAGG
F2h0dHA6Ly9vY3NwLmVudHJ1c3QubmV0MC4GCCsGAQUFBzAChiJodHRwOi8vYWlh
LmVudHJ1c3QubmV0L2wxai1lYzEuY2VyMDMGA1UdHwQsMCowKKAmoCSGImh0dHA6
Ly9jcmwuZW50cnVzdC5uZXQvbGV2ZWwxai5jcmwwSgYDVR0gBEMwQTA2BgpghkgB
hvpsCgECMCgwJgYIKwYBBQUHAgEWGmh0dHA6Ly93d3cuZW50cnVzdC5uZXQvcnBh
MAcGBWeBDAEBMB8GA1UdIwQYMBaAFMP5RQO+yPkLPEU18+ty7Ofo65SbMB0GA1Ud
DgQWBBRnLUA80+dPY+cg+vx7O/iK/e0lRzAJBgNVHRMEAjAAMAoGCCqGSM49BAMC
A2gAMGUCMQDKTonUpaa+kPAtGe8uJQpvILHFNQQlL7IMkfw7KwimpWOLM2Zuuu3c
xSl3uLJD1wACME4Mk3XWRUFXAR8d//6kfcWjmI/6sgtAwbqRnWeFyoSG2WEvYyoy
2i8EqeX8hBfDZA==
-----END CERTIFICATE-----
`)

func TestCertificate(t *testing.T) {
	for _, cert := range parseCertficates(letsencryptChain, t) {
		t.Log(cert.CRLDistributionPoints)
		t.Log(cert.OCSPServer)
	}
}

func TestChainListing(t *testing.T) {
	certs := parseCertficates(letsencryptChain, t)
	c := newCertutil(t)
	defer c.Delete()
	for _, cert := range certs {
		c.Install(cert)
	}
	t.Log(c.ListChain(certs[0]))
	for _, cert := range certs {
		out, err := c.Verify(cert)
		t.Log(string(out), err)
	}

}

func TestAThing(t *testing.T) {
	c, err := NewCertutil()
	if err != nil {
		t.Fatal(err)
	}
	//for _, cc := range letsencryptChain {
	//	cert := parseCertificate(cc, t)
	//	c.Install(cert)
	//}
	cert, err := NewCertificate(letsencrypt)
	if err != nil {
		t.Fatal(err)
	}
	c.Install(cert)
	//out, err := c.Install(cert)
	//if err != nil {
	//	t.Log(out)
	//	t.Fatal(err)
	//}
	//out, err = c.Verify(cert)
	//t.Log(string(out))
	//t.Log(err)
}

func TestCertutilValid(t *testing.T) {
	certutil, err := NewCertutil()
	if err != nil {
		t.Fatal(err)
	}
	defer certutil.Delete()
	cert := parseCertificate(letsencrypt, t)
	out, err := certutil.Install(cert)
	if err != nil {
		t.Log(string(out))
		t.Fatal(err)
	}
	out, err = certutil.Verify(cert)
	if err != nil {
		t.Log(string(out))
		t.Fatal(err)
	}
	if !bytes.HasSuffix(out, []byte("certificate is valid")) {
		t.Fatal(string(out))
	}
}

func TestCertutilInvalid(t *testing.T) {
	certutil, err := NewCertutil()
	if err != nil {
		t.Fatal(err)
	}
	defer certutil.Delete()
	cert := parseCertificate(expiredEnstrust, t)
	out, err := certutil.Install(cert)
	if err != nil {
		t.Log(string(out))
		t.Fatal(err)
	}
	out, err = certutil.Verify(cert)
	if err == nil {
		t.Fatal("Expected an error from certutil")
	}
	if !bytes.HasSuffix(out, []byte("Peer's Certificate has expired.")) {
		t.Fatal(string(out))
	}
}

func parseCertificate(p []byte, t *testing.T) *Certificate {
	cert, err := NewCertificate(p)
	if err != nil {
		t.Fatal(err)
	}
	return cert
}

func parseCertficates(p [][]byte, t *testing.T) []*Certificate {
	var certs []*Certificate
	for _, c := range p {
		certs = append(certs, parseCertificate(c, t))
	}
	return certs
}

func newCertutil(t *testing.T) Certutil {
	c, err := NewCertutil()
	if err != nil {
		t.Fatal(err)
	}
	return c
}

func TestGetThing(t *testing.T) {
	url := "https://revokedec.entrust.net"
	resp, err := http.DefaultClient.Get(url)
	if err != nil {
		t.Log(err)
	}
	var certs []*Certificate
	for _, i := range resp.TLS.PeerCertificates {
		cert := new(Certificate)
		cert.Certificate = i
		hasher := crypto.SHA256.New()
		hasher.Write(cert.Raw)
		cert.Fingerprint = string(hasher.Sum([]byte{}))
		certs = append(certs, cert)
	}
	c := newCertutil(t)
	defer c.Delete()
	for _, cert := range certs {
		out, err := c.Install(cert)
		t.Log(cert.Subject.CommonName)
		t.Log(cert.Issuer.CommonName)
		if err != nil {
			t.Fatal(errors.Wrapf(err, string(out)))
		}
	}
	for _, cert := range certs {
		out, err := c.Verify(cert)
		if err != nil {
			t.Fatal(errors.Wrapf(err, string(out)+" "+cert.Issuer.CommonName))
		}
	}
}
