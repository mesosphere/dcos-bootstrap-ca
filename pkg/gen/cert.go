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

const validFor = time.Hour * 24 * 365 * 100

// BasicCertificateConfig DI for certificate generation
type BasicCertificateConfig struct {
	name           pkix.Name // Subject data for x509 certificates
	isCA           bool      // true if the certificate can sign other certificates
	hosts          []string  // A list of DNS names and ip addresses
	emailAddresses []string  // administrative email address associated with the certificate
}

// MakeCertificateConfig packs a pkix.Name struct and returns a BasicCertificateConfig structure
func MakeCertificateConfig(name, country, state, locality, organization string,
	hosts, emailAddresses []string, ca bool) BasicCertificateConfig {

	dn := pkix.Name{
		CommonName:   name,
		Country:      []string{country},
		Province:     []string{state},
		Locality:     []string{locality},
		Organization: []string{organization},
	}

	return BasicCertificateConfig{
		name:           dn,
		emailAddresses: emailAddresses,
		isCA:           ca,
		hosts:          hosts,
	}

}

func generateSerialNumber() (*big.Int, error) {
	serialNumberLimit := new(big.Int).Lsh(big.NewInt(1), 128)
	return rand.Int(rand.Reader, serialNumberLimit)
}

// GenerateCertificate simplifies certificate generation. Certificates are returned as a byte slice.
func GenerateCertificate(
	config BasicCertificateConfig, issuer *x509.Certificate, key *rsa.PrivateKey) ([]byte, error) {
	var pubKey *rsa.PublicKey

	serialNumber, err := generateSerialNumber()
	if err != nil {
		log.Printf("failed to generate serial number: %s", err)
		return nil, err
	}

	notBefore := time.Now()
	notAfter := notBefore.Add(validFor)

	template := x509.Certificate{
		SerialNumber:   serialNumber,
		Subject:        config.name,
		EmailAddresses: config.emailAddresses,

		NotBefore: notBefore,
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
		pubKey = key.Public().(*rsa.PublicKey)
	} else {
		pubKey = issuer.PublicKey.(*rsa.PublicKey)
	}

	log.Printf("Generating certificate - SN: %x", template.SerialNumber)
	return x509.CreateCertificate(rand.Reader, &template, issuer, pubKey, key)
}

// Sign issues and signs a certificate per the csr provided.
func Sign(csr *x509.CertificateRequest, issuer *x509.Certificate, signingKey *rsa.PrivateKey) ([]byte, error) {
	if err := csr.CheckSignature(); err != nil {
		log.Printf("CSR signature is not valid: %v", err)
		return nil, err
	}

	serialNumber, err := generateSerialNumber()

	if err != nil {
		log.Printf("failed to generate serial number: %s", err)
		return nil, err
	}

	notBefore := time.Now()
	notAfter := notBefore.Add(validFor)

	template := x509.Certificate{
		SerialNumber:   serialNumber,
		Subject:        csr.Subject,
		EmailAddresses: csr.EmailAddresses,

		NotBefore: notBefore,
		NotAfter:  notAfter,

		BasicConstraintsValid: true,

		IPAddresses: csr.IPAddresses,
		DNSNames:    csr.DNSNames,
	}

	log.Printf("Generating certificate - SN: %x", template.SerialNumber)

	return x509.CreateCertificate(rand.Reader, &template, issuer, csr.PublicKey, signingKey)
}
