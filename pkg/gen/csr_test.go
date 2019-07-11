package gen

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"testing"
)

func TestCSRGeneration(t *testing.T) {
	pKey, _ := rsa.GenerateKey(rand.Reader, 2048)
	config := MakeCSRConfig(
		"client",
		"US",
		"TX",
		"San Antonio",
		"Mesosphere Inc.",
		[]string{"192.168.1.2", "exhibitor", "127.0.0.1", "localhost"},
		[]string{"security@mesosphere.com"},
	)

	csrBytes, err := GenerateCSR(config, pKey)
	if err != nil {
		t.Fatalf("csr generation failed: %v", err)
	}

	csr, err := x509.ParseCertificateRequest(csrBytes)
	if err != nil {
		t.Fatalf("csr is invalid: %v", err)
	}

	if csr.Subject.CommonName != "client" {
		t.Errorf("CommonName is incorrect: %v", csr.Subject.CommonName)
	}

	if len(csr.EmailAddresses) != 1 && csr.EmailAddresses[0] != "security@mesosphere.com" {
		t.Errorf("Email address is incorrect: %v", csr.EmailAddresses)
	}
}
