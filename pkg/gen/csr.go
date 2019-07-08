package gen

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"log"
	"net"
)

type CSRConfig struct {
	name           pkix.Name
	emailAddresses []string
	hosts          []string
}

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
