// x509 CSR and certificate generation

package gen

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"log"
	"math/big"
	"net"
	"time"
)

var validFor = time.Hour*24*365*100

type basicCertificateConfig struct {
	name  *pkix.Name
	isCA  bool
	hosts []string
}

func MakeCertificateConfig(name, country, state, locality, organization string,
	hosts []string, ca bool) *basicCertificateConfig {

	dn := pkix.Name{
		CommonName: name,
		Country: []string{country},
		Province: []string{state},
		Locality: []string{locality},
		Organization: []string{organization},
	}
	return &basicCertificateConfig{
		name:  &dn,
		isCA:  ca,
		hosts: hosts,
	}

}
func GenerateCertificate(
	config *basicCertificateConfig, issuer *x509.Certificate, key *rsa.PrivateKey) ([]byte, error) {
	serialNumberLimit := new(big.Int).Lsh(big.NewInt(1), 128)
	serialNumber, err := rand.Int(rand.Reader, serialNumberLimit)

	if err != nil {
		log.Fatalf("failed to generate serial number: %s", err)
		return nil, err
	}

	notBefore := time.Now()
	notAfter := notBefore.Add(validFor)

	template := x509.Certificate{
		SerialNumber: serialNumber,
		Subject:      *config.name,

		NotBefore: time.Now(),
		NotAfter:  notAfter,

		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,

		IsCA: config.isCA,
	}

	for _, h := range config.hosts {
		if ip := net.ParseIP(h); ip != nil {
			template.IPAddresses = append(template.IPAddresses, ip)
		} else {
			template.DNSNames = append(template.DNSNames, h)
		}
	}


	if template.IsCA {
		template.KeyUsage |= x509.KeyUsageCertSign
	}

	// Self-signed
	if issuer == nil {
		issuer = &template
	}

	log.Printf("Generating certificate - SN: %x", template.SerialNumber)
	return x509.CreateCertificate(rand.Reader, issuer, &template, &key.PublicKey, key)
}