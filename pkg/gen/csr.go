package gen

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"log"
	"net"
)

// CSRConfig DI for CSR generation
type CSRConfig struct {
	name           pkix.Name
	emailAddresses []string
	hosts          []string
}

// MakeCSRConfig helps to generate the pkix.Name structure needed for CSR generation
func MakeCSRConfig(name, country, state, locality, organization string, hosts, emailAddresses []string) CSRConfig {
	dn := pkix.Name{
		CommonName:   name,
		Country:      []string{country},
		Province:     []string{state},
		Locality:     []string{locality},
		Organization: []string{organization},
	}
	return CSRConfig{
		name:           dn,
		emailAddresses: emailAddresses,
		hosts:          hosts,
	}
}

// GenerateCSR simplifies CSR generation. CSRs are returned as byte slices
func GenerateCSR(config CSRConfig, key *rsa.PrivateKey) ([]byte, error) {
	template := x509.CertificateRequest{
		Subject:        config.name,
		EmailAddresses: config.emailAddresses,
	}

	for _, h := range config.hosts {
		if ip := net.ParseIP(h); ip != nil {
			template.IPAddresses = append(template.IPAddresses, ip)
		} else {
			template.DNSNames = append(template.DNSNames, h)
		}
	}
	log.Printf("Generating CSR - CN: %s", config.name.CommonName)
	return x509.CreateCertificateRequest(rand.Reader, &template, key)
}

// DecodeAndParsePEM combines PEM decode and CSR parsing
func DecodeAndParsePEM(data []byte) (*x509.CertificateRequest, error) {
	block, _ := pem.Decode(data)
	if block == nil {
		return nil, errors.New("no PEM information to parse in data")
	}

	return x509.ParseCertificateRequest(block.Bytes)
}
