package gen

import (
	"crypto/x509"
	"encoding/pem"
	"github.com/jr0d/dcoscertstrap/pkg/gen"
	"github.com/spf13/afero"
	"os"
	"testing"
)

const testStorePath = "/test/.pki"

func TestInitStorage(t *testing.T) {
	gen.AppFs = afero.NewMemMapFs()
	err := gen.InitStorage(testStorePath)
	if err != nil {
		t.Fatalf("error creating storage directory: %v", err)
	}

	fileInfo, err := gen.AppFs.Stat(testStorePath)
	if err != nil {
		t.Fatalf("could not stat %s: %v", testStorePath, err)
	}

	expected := os.FileMode(0700) | os.ModeDir
	if fileInfo.Mode() != expected {
		t.Fatalf("storage directory created with incorrect permissions: got %s, expected :%s",
			fileInfo.Mode(), expected)
	}
}

func TestWritePrivateKey(t *testing.T) {
	key := []byte(`-----BEGIN RSA PRIVATE KEY-----
MIIEowIBAAKCAQEA3qsP+/dmr/YPAZhD7bOT/obGqNQ4a9+o4wPwE20sDIvzWJev
nO1kqzOfJK7t2zXP8Y+q9uQT3TaRfvVInEgdOiNrB8U5/hL8t0OKmKs8SGi7FrA7
vBYtCfHMdqupvWZRvagg8SsQXh9K6GPUoothgxivkf9uZQOoYlkk7ijPvupzd7r1
dOOkQHhLZdUaAfHTVANbUJkmD9IpLKAt4+sadpkNtEFCasRFOU3AtW1DREfc0mpe
QCRt8hiFrkkgI73CPZxjVZ54fu1YV3guf/nrneEhFbhs8szuFTxq3aLG6eAX4DkS
0H+vKrfRvE0KEUMjehGm637Njift7nQZJakuuQIDAQABAoIBAGQX2XOWXt6yaUR6
Qe7UTq6Xvy2dWE+FltGVr5HL/YUWVCl65kJQpHQhHGTNDbcAlZ0sy9l35UYHhZfg
gudds2WzDiXMDqmbt2ZaQi8mqk6SZadpSTDfdxeFTjf6Kq8tE4mBzm0awpzMzEty
tN7scMURj7q9a86UulibYfJ8/gX/XzWWjGvVyPrIjQo9MCqAl5HXkus7LvQAxhxk
z58e1QIUaApZkEGgg8aERh/1jR/1d2Yohrto7AHsrsnvw+8Dx8nvisX3AmZm5qGn
w/WfjiO9kpFhiD76QpbJNeI/G1LABrWe0uPXEI1ZIPlRKE5DPfUq9JJofHMvKv5q
pVtjgxECgYEA/FnUJg2GIfGwn0FEr8l15w7VQe1fcQOCnZWjINipNW4rNAqTSzyV
0PcEeo+0EJI38xGnReBOkWgDMvgRsrfOAZtqa9JRWHVXIYnDVRNcIl9TdKSUsuIX
fVPIqk1DMTo1iom70IuI2WgPXkTsla1CcxERxuzZHNAXZNbw/GsuHA8CgYEA4eNa
KGadvI8SILND47S9qz/wXE8dz8AEYMGukKRiW8MAyvh22ZKg1XQYbprUTPXR1tAF
nb7D5Wm3d7UU//D/F3JWfg1Ha+dxL8/pAi88doYo0VSRGWeehUoFoUA15SEOQ1JW
8zRMMx6UuPaKmmwJNAEP6yP4HSiarwAJHDB64LcCgYEAvKXmq9/WU0/cCuH/GC7S
Hj5/fH6Yp+LI5Ud1INv3ewL19zykqk0LbqELTxhYsz6r5uFenCU4dwk7wwGiMWmo
7pihsSMUPr3RujfDt7j2WpfKytsycpwElWNqEq4ZuhZa6ktXBWsajfR18LIz7x0M
HPs4v+5VzG1f37mzg/AYE08CgYA0mbmb4NFoYDSLctMjSipEn338MNwzTXZ3hYJ9
4hmZXp5npVYfshpLul4aG2nGhhOYHxa/tfVuDaEQehVqyBbOwexMLBFumhVsWdDb
ll5RB0qn/DZRoSRzy1nmQ8qJEZp9qMXgmlQIL13YeGisLu4xsvGfAuA7AgKLL8nv
S4bBnwKBgClpuz0qoO2QSR3UhUb+JeVclYDbUMsfTsVrA6PM4pSRry5ROJLd7a0r
PzIDeK7yKWGcklqhG17IVS5VUotwFyYWJP+mhkM92cG8YQaKAnJwSzwa3KPUoZSM
fK2XHqIW9vWiBCBpTU96wTjellzmn3K+D46CBOwwoL+OBRC3I2ZC
-----END RSA PRIVATE KEY-----`)
	gen.AppFs = afero.NewMemMapFs()
	_ = gen.InitStorage(testStorePath)
	p := gen.StorePath("private.key")
	tmp, _ := pem.Decode(key)
	pKey, _ := x509.ParsePKCS1PrivateKey(tmp.Bytes)
	e := gen.WritePrivateKey(p, pKey)
	if e != nil {
		t.Fatalf("failed to write private key: %v", e)
	}

	fileInfo, err := gen.AppFs.Stat(p)
	if err != nil {
		t.Fatalf("could not stat %s: %v", p, e)
	}

	mode := fileInfo.Mode()

	if mode != os.FileMode(0600) {
		t.Fatalf("private key file does not have the correct permissions: %s", mode.Perm())
	}

	resultKey, err := gen.ReadPrivateKey(p)

	if err != nil {
		t.Fatalf("error parsing private key")
	}

	pKeyBytes := pKey.D.Bytes()
	resultKeyBytes := resultKey.D.Bytes()

	for i := 0; i < len(pKeyBytes); i++ {
		if pKeyBytes[i] != resultKeyBytes[i] {
			t.Fatalf("Keys differ - I: %d , L: %x , R: %x", i, pKeyBytes[i], resultKeyBytes[i])
		}
	}
}

func TestWriteCertificate(t *testing.T) {
	cert := []byte(`-----BEGIN CERTIFICATE-----
MIIDkjCCAnqgAwIBAgIQLwHsHiPCDIpJOVM3DY0IZDANBgkqhkiG9w0BAQsFADBZ
MQswCQYDVQQGEwJVUzELMAkGA1UECBMCVFgxFDASBgNVBAcTC1NhbiBBbnRvbmlv
MRgwFgYDVQQKEw9NZXNvc3BoZXJlIEluYy4xDTALBgNVBAMTBFJPT1QwIBcNMTkw
NzA1MTg0NjIwWhgPMjExOTA2MTExODQ2MjBaMFkxCzAJBgNVBAYTAlVTMQswCQYD
VQQIEwJUWDEUMBIGA1UEBxMLU2FuIEFudG9uaW8xGDAWBgNVBAoTD01lc29zcGhl
cmUgSW5jLjENMAsGA1UEAxMEUk9PVDCCASIwDQYJKoZIhvcNAQEBBQADggEPADCC
AQoCggEBAK5LKHmpUvBXG99V/DZgePQmyNNR2c9YBqIdUTUUH2CmYxw9BqgA2npo
tx9RUcQG80FQt/Wt0plKQyP2+ywy3yXqSTatU0m4mjDhSDLCldEyfODuUrjZYhGI
BjXkMzlZb5WUR3ikWfhjpKnfgjJAYcgi1wlfD2JiB6yeGw4NV8NoyPuSBhgspzvO
okAvXb6nn3wFgnJ5HSzPjpNtUc96Zqte7GejTNrpXrJ/iMpFGuhtcYaDLGPNPmUQ
DjO/824cQOzamoROW4lx5VKGIxD1vPbkEo+6jBmj92ojyqBVz3UaAbzJp98JAtSR
t5nZp40GZu7ZISUsqM4+kJkAg1ZN2lUCAwEAAaNUMFIwDgYDVR0PAQH/BAQDAgKk
MBMGA1UdJQQMMAoGCCsGAQUFBwMBMA8GA1UdEwEB/wQFMAMBAf8wGgYDVR0RBBMw
EYIJbG9jYWxob3N0hwR/AAABMA0GCSqGSIb3DQEBCwUAA4IBAQCpyivutpGr5nfv
7vAPqcf98FY7UrdKMLlDzIUYkzqngpj6+fL9PzxH+3TbtPNL2404E+4+exHZMK00
dky2kwihO6ryVszlpu1SulsGVPNO9pBusXzy0IYSwyVz6Cqipx+NR74iEkNTigrp
DsvhbCrOWBo2w8q02mUbLTW3MfZB0CpauWOxtUrqPmQ1dGgYA6aCg0ZGzVp3/3V6
5V7OEh5jbVYoEiaotfq0/c9LUTcP5nyCBqkovorgKRaIKobwKX1aaqB+A6gHBEAT
t5ffjQkLvSjaPUuf5PxLAatgAR+WbRDq+suuHmHTlOYftRWCvmuBvyaNieGExbjw
TxYx+J5Z
-----END CERTIFICATE-----
`)
	gen.AppFs = afero.NewMemMapFs()
	_ = gen.InitStorage(testStorePath)
	p := gen.StorePath("test-cert.pem")
	block, _ := pem.Decode(cert)
	testCert, _ := x509.ParseCertificate(block.Bytes)
	if err := gen.WriteCertificate(p, block.Bytes); err != nil {
		t.Fatalf("error writing certificate: %v", err)
	}

	bytes, err := gen.ReadCertificatePEM(p)
	if err != nil {
		t.Fatalf("error reading file: %v", err)
	}
	readCert, err := x509.ParseCertificate(bytes)
	if err != nil {
		t.Fatalf("error parsing certificate: %v", err)
	}

	if testCert.SerialNumber.Cmp(readCert.SerialNumber) != 0 {
		t.Fatalf("certificates differ")
	}
}
