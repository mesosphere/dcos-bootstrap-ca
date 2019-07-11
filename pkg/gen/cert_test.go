package gen

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"testing"
)

func TestCertificateGeneration(t *testing.T) {
	pKey, _ := rsa.GenerateKey(rand.Reader, 2048)
	config := MakeCertificateConfig(
		"ROOT",
		"US",
		"TX",
		"San Antonio",
		"Mesosphere Inc.",
		[]string{"localhost", "127.0.0.1"},
		[]string{"security@mesosphere.com"},
		true)

	fmt.Printf("%x", pKey)
	rootCert, err := GenerateCertificate(config, nil, pKey)
	if err != nil {
		t.Fatalf("certificate generation failed: %v", err)
	}

	cert, err := x509.ParseCertificate(rootCert)

	if err != nil {
		t.Fatalf("certificate is invalid: %v", err)
	}

	if cert.Subject.CommonName != "ROOT" {
		t.Fatalf("certificate has an incorrect CN: %s", cert.Subject.CommonName)
	}
}

func TestCertificateSigning(t *testing.T) {
	rootKeyPem := []byte(`-----BEGIN RSA PRIVATE KEY-----
MIIEowIBAAKCAQEArwEKyB78WEkdVP10e7ev5LjM8KINChuY70nDfZglNHlMUj1P
0UlbxnrhMYGBrCgOw4ybrpYg0g8wKA7p/I4+mSppNWoNoqQMekOJFDFIXoCgznsN
DLGdTF3UQx7igLoxD1dPrm11u98OijOBhM4tmPcoDICfXQ+uIry143t3tRgIk2tj
yzfKC3VfkUCqgDZ5Uq0eECtm2TVAbCr459wNxJ8bsbHh6KGsnISOmHOiujX2pD18
u2H3pzyaHkGSXXsAU5Nggla8sXKS1Hb321HLjzBr8FcP1wEZ8Io4//cHL5IlrCnd
xNVb+2Ccrssfi4Bnj3EssomQdk5PtyXih2RsVwIDAQABAoIBAAKwYmkGyNvWa8P1
jQeln+dEy6la5BZmrCfpGz7fypqOzpRo6sQNe4KGOtWW5tYtW2S30WCSX/i6UQQc
jo3Z5a5Wz30JnyIDoUlzpjSQOUtycIYbr+ylAgS9YFiTrelKcxyIO+ozNl7no4KO
HgxbWqoCCjR++XPlnMhd2/Gd4Q4ARQbr8ApaMR+3TCvVJJzLvSrCjd+amw51X/9D
OBuUqKOG44Ljuj0FFJqEw4v9StpYMRblm+Kq7+LEw2Nvklb/OYcIn1V2gtpFITZ2
fCNKqgrBoJEwtS60PfspquC+jP+RWP+HYnWKPRI6aVsP703WNFAW1Igfopoi8E+D
62tER0kCgYEA3F7jRDW6mN7LOjZBAmVSxJDqd1+NHUTWqiChF71ynCWh4ufvBkIl
uO+u1y7hFh4AkZQ/WxewzhJ2Ik3HylL4iUQnH78/uCZU9XiXFgD8d2SFEwXs0R3d
Bmr0keInqwjGVFm5BrNzJFhp63l/H7aqKMP/gKU3dBUyIkEvczTjaYMCgYEAy0xv
+2kyE3Q/ZulIQCT4DZtxpeMWHJD0dhnpHjq9ygrmE/uHFWwvyA0XSef1/VJ5KUxR
00Tptn5+OsA3O5EaWwfCFggF554vy7sHpGNokJBxDHEU/IVtHhidA81eCwZsFj9G
5ZPgJ8GaAe4KklIJ0GNudq1v7KTZdUotng0tvZ0CgYBZ4XG8XlWvCB/HrF0zhvQN
LDYVXimGKI+NcCWEM0bNnSO8EnEREmWkWk3rgjlX9gCxX8+/bZg1VJ5OO38jbFfm
VJ/IeQ6aIzg/rmGhHeHbKGqGacI/QHjnpzP9VEptnfSWbsnii8qIpm79Fd7dpnkc
i2RoqfpGJGcARan+yTF/1QKBgFQzrI3s3BjCpR/yr0IiDbtVDpUuoRHj19yyjqM+
oSz1pqXQH/r3fDLXeTXbJT9u0VARlDJ08HftnEqpIjdBujDJ3dFSMV/lXNZ8+IVV
xxFZQfltPMv6V1+HwkC45qKaXlo4ixy7SrQss6To+ufvorD0/eOZoinZfVffCVXV
D4ThAoGBAMxufBkdgQRCajfMkGnh0yW03lms6QD3B8HseLzbuuccyISKjcIR1NkL
icWjMcwRNcwnRcTzSjbVZiiIbfm+NZMlmR/fTHWozq0YFIZv0l//Kafp73lvaOp0
P6PKpCK+c++n0HaZANDxlIdZaJFL+DqGkiT18qBC1k+R94afEdME
-----END RSA PRIVATE KEY-----`)

	block, _ := pem.Decode(rootKeyPem)
	rootKey, err := x509.ParsePKCS1PrivateKey(block.Bytes)
	if err != nil {
		t.Fatalf("error parsing root private key: %v", err)
	}
	caCertPem := []byte(`-----BEGIN CERTIFICATE-----
MIIDuzCCAqOgAwIBAgIRAMuO8ijU5zlyvRUtguta2fwwDQYJKoZIhvcNAQELBQAw
WDELMAkGA1UEBhMCVVMxCzAJBgNVBAgTAlRYMRQwEgYDVQQHEwtTYW4gQW50b25p
bzEXMBUGA1UEChMOTWVzb3NwaGVyZSBJbmMxDTALBgNVBAMTBFJPT1QwIBcNMTkw
NzA4MTYwOTM5WhgPMjExOTA2MTQxNjA5MzlaMFgxCzAJBgNVBAYTAlVTMQswCQYD
VQQIEwJUWDEUMBIGA1UEBxMLU2FuIEFudG9uaW8xFzAVBgNVBAoTDk1lc29zcGhl
cmUgSW5jMQ0wCwYDVQQDEwRST09UMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIB
CgKCAQEArwEKyB78WEkdVP10e7ev5LjM8KINChuY70nDfZglNHlMUj1P0Ulbxnrh
MYGBrCgOw4ybrpYg0g8wKA7p/I4+mSppNWoNoqQMekOJFDFIXoCgznsNDLGdTF3U
Qx7igLoxD1dPrm11u98OijOBhM4tmPcoDICfXQ+uIry143t3tRgIk2tjyzfKC3Vf
kUCqgDZ5Uq0eECtm2TVAbCr459wNxJ8bsbHh6KGsnISOmHOiujX2pD18u2H3pzya
HkGSXXsAU5Nggla8sXKS1Hb321HLjzBr8FcP1wEZ8Io4//cHL5IlrCndxNVb+2Cc
rssfi4Bnj3EssomQdk5PtyXih2RsVwIDAQABo34wfDAOBgNVHQ8BAf8EBAMCAqQw
EwYDVR0lBAwwCgYIKwYBBQUHAwEwDwYDVR0TAQH/BAUwAwEB/zBEBgNVHREEPTA7
gglleGhpYml0b3KCCWxvY2FsaG9zdIEXc2VjdXJpdHlAbWVzb3NwaGVyZS5jb22H
BMCoAQKHBH8AAAEwDQYJKoZIhvcNAQELBQADggEBAAWBM7egtLG4UNZaSsKJuEwm
odiztn+nehXznoacpZR8WC3ep8swOvvq0/7cXXjikSd6v9gItIrVO5vpN7ZDbitP
X+ZWfcZg9NGD0KJGJXsujXFyMTDoy5KcX7RYNQFNhy+ZZJsnaW+UXGZnklNsAEWH
lrwoq9l51OLwpR0xyoqcqcNz10sAon/CDPUVIW464gBgz1zJM/ObhByJ9LOCp7aD
B8FmeVyfub//nRsW9Ea+jOWciaUl/EyfOkkx7gHvuEuFu675RRojDTIneCmblWOx
oWqnlJdCFaFu6n1nbtO9GKgKOe/qPCNn/rVqgzDn8KFj4tRUxUYdLyXRLkSx9Ck=
-----END CERTIFICATE-----`)
	block, _ = pem.Decode(caCertPem)
	caCert, _ := x509.ParseCertificate(block.Bytes)
	clientKey, _ := rsa.GenerateKey(rand.Reader, 2048)

	config := MakeCSRConfig(
		"test",
		"US",
		"TX",
		"San Antonio",
		"Mesosphere Inc.",
		[]string{"127.0.0.1", "localhost", "192.168.1.10"},
		[]string{"security@mesosphere.com"},
	)

	csrBytes, err := GenerateCSR(config, clientKey)
	if err != nil {
		t.Fatalf("error generating csr: %v", err)
	}
	csr, err := x509.ParseCertificateRequest(csrBytes)
	if err != nil {
		t.Fatalf("error parsing csr: %v", err)
	}

	signed, err := Sign(csr, caCert, rootKey)
	if err != nil {
		t.Fatalf("error granting CSR: %v", err)
	}

	signedCert, err := x509.ParseCertificate(signed)
	if err != nil {
		t.Fatalf("error parsing certificate: %v", err)
	}

	if signedCert.Issuer.CommonName != caCert.Subject.CommonName {
		t.Fatalf("%s != %s", signedCert.Issuer.CommonName, caCert.Subject.CommonName)
	}
}
