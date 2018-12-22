package certutil

import (
	"bytes"
	"fmt"
	"io/ioutil"
	"log"
	"os"
	"os/exec"
	"path"

	"github.com/pkg/errors"
)

const (
	NewCertificateDatabase = "-N"
	NoPassword             = "--empty-password"
	CertDbDirectory        = "-d"

	InstallCert = "-A"
	CertName    = "-n"
	TrustArgs   = "-t"
	TrustedPeer = "P,p,p"
	TrustedCA   = "C,p,p"

	Verify          = "-V"
	VerifySignature = "-e"
	CertUsage       = "-u"
	SSLServer       = "V"

	ListChain = "-O"
)

var executable = "certutil"
var db string

func Init(dbDir string, dist string) error {
	db = dbDir
	ldpath := os.Getenv(LIBRARY_PATH)
	ldpath = ldpath + ":" + path.Join(dist, "lib")
	if err := os.Setenv(LIBRARY_PATH, ldpath); err != nil {
		return err
	}
	binPath := os.Getenv("PATH")
	if err := os.Setenv("PATH", binPath+":"+path.Join(dist, "bin")); err != nil {
		return err
	}
	help, err := execute([]string{})
	if !bytes.Contains(help, []byte("certutil - Utility to manipulate NSS certificate databases")) {
		return errors.Wrap(err, fmt.Sprintf("Failed to load '%s' given the PATH=%s\n$ certutil\n%s", executable, os.Getenv("PATH"), string(help)))
	}
	return nil
}

type Certutil struct {
	tmpDir string
}

func NewCertutil() (certutil Certutil, err error) {
	tmpDir, err := ioutil.TempDir("", "")
	if err != nil {
		return
	}
	certutil.tmpDir = tmpDir
	out, err := execute([]string{NewCertificateDatabase, NoPassword, CertDbDirectory, certutil.tmpDir})
	if err != nil {
		log.Println(string(out))
	}
	return
}

//-t trustargs      Set the certificate trust attributes:
//trustargs is of the form x,y,z where x is for SSL, y is for S/MIME,
//and z is for code signing. Use ,, for no explicit trust.
//p 	 prohibited (explicitly distrusted)
//P 	 trusted peer
//c 	 valid CA
//T 	 trusted CA to issue client certs (implies c)
//C 	 trusted CA to issue server certs (implies c)
//u 	 user cert
//w 	 send warning
//g 	 make step-up cert
func (c Certutil) Install(cert *Certificate) ([]byte, error) {
	var trustArgs string
	switch cert.IsCA {
	case true:
		trustArgs = TrustedCA
	case false:
		trustArgs = TrustedPeer
	}
	return execute([]string{
		InstallCert,
		TrustArgs, trustArgs,
		CertName, cert.Fingerprint,
		CertDbDirectory, c.tmpDir,
		"-4",
	}, cert.Raw...)
}

func (c Certutil) InstallCA(cert *Certificate) ([]byte, error) {
	return execute([]string{
		InstallCert,
		TrustArgs, "C",
		CertName, cert.Fingerprint,
		CertDbDirectory, c.tmpDir,
	}, cert.Raw...)
}

//-u certusage      Specify certificate usage:
//C 	 SSL Client
//V 	 SSL Server
//I 	 IPsec
//L 	 SSL CA
//A 	 Any CA
//Y 	 Verify CA
//S 	 Email signer
//R 	 Email Recipient
//O 	 OCSP status responder
//J 	 Object signer
func (c Certutil) Verify(cert *Certificate) ([]byte, error) {
	var certUsage string
	switch cert.IsCA {
	case true:
		certUsage = "L"
	case false:
		certUsage = "V"
	}
	return execute([]string{
		Verify,
		"-e",
		CertName, cert.Fingerprint,
		CertUsage, certUsage,
		CertDbDirectory, c.tmpDir,
	})
}

func (c Certutil) VerifyCA(cert *Certificate) ([]byte, error) {
	return execute([]string{
		Verify,
		CertName, cert.Fingerprint,
		CertUsage, "L",
		CertDbDirectory, c.tmpDir,
	})
}

func (c Certutil) ListChain(cert *Certificate) ([]Fingerprint, error) {
	out, err := execute([]string{
		ListChain,
		CertName, cert.Fingerprint,
		CertDbDirectory, c.tmpDir,
	})
	if err != nil {
		return []Fingerprint{}, errors.Wrap(err, string(out))
	}
	var fingerprints []Fingerprint
	fmt.Print(string(out))
	for _, link := range bytes.Split(out, []byte{byte('\n')}) {
		fingerprints = append(fingerprints, string(bytes.TrimSpace(link)))
	}
	return fingerprints, nil
}

func (c Certutil) Delete() error {
	return os.RemoveAll(c.tmpDir)
}

func execute(args []string, input ...byte) ([]byte, error) {
	cmd := exec.Command(executable, args...)
	cmd.Stdin = bytes.NewBuffer(input)
	out, err := cmd.CombinedOutput()
	return bytes.TrimSpace(out), err
}
