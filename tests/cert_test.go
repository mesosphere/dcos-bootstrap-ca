package tests

import (
	"crypto/x509"
	"testing"
)

import "github.com/jr0d/dcoscertstrap/pkg/gen"

func TestCertificateGeneration(t *testing.T) {
	pKey, _ := gen.GenerateRSAPrivateKey()
	config := gen.MakeCertificateConfig(
		"ROOT",
		"US",
		"TX",
		"San Antonio",
		"Mesosphere Inc.",
		[]string{"localhost", "127.0.0.1"},
		true)

	rootCert, err := gen.GenerateCertificate(config, nil, pKey)
	if err != nil {
		t.Errorf("Wow: %v", err)
	}
	cert, err := x509.ParseCertificate(rootCert)
	if err != nil {
		t.Errorf("Certificate is invalid: %v", err)
	}

	if cert.Subject.CommonName != "ROOT" {
		t.Errorf("Certificate has an incorrect CN")
	}
}