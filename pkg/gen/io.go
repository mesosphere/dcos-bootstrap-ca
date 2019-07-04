// Encoding and storage functions

package gen

import (
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"os"
	"path"
)

var storagePath string

// DRY: Used to create PEM files of various types
func writePem(filePath string, der []byte, blockType string, private bool) error {
	var mode os.FileMode
	if private {
		mode = 0600
	} else {
		mode = 0644
	}
	out, err := os.OpenFile(filePath, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, mode)
	if err != nil {
		return nil
	}
	return pem.Encode(out, &pem.Block{Type: blockType, Bytes: der})
}

// Writes a PrivateKey PEM with restrictive permissions
func WritePrivateKey(filePath string, key *rsa.PrivateKey) error {
	return writePem(
		filePath, x509.MarshalPKCS1PrivateKey(key), "RSA PRIVATE KEY", true)
}

// Writes a X509 certificate
func WriteCertificate(filePath string, certificate []byte) error {
	return writePem(filePath, certificate, "CERTIFICATE", false)
}

// Creates the storage directory, if it does not already exist. This
// function also sets the storagePath global
func InitStorage(dirPath string) error {
	storagePath = dirPath
	return os.MkdirAll(dirPath, 0700)
}

// Appends filePath to storagePath
func StorePath(filePath string) string {
	return path.Join(storagePath, filePath)
}
