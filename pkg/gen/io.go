// Encoding and storage functions

package gen

import (
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"log"
	"os"
	"path"

	"github.com/spf13/afero"
)

var storagePath string

// AppFs: OsFS is the default file system abstraction.
var AppFs = afero.NewOsFs()

func Close(c io.Closer) {
	if e := c.Close(); e != nil {
		log.Fatalf("error closing %v: %v", c, e)
	}
}

// DRY: Used to create PEM files of various types
func writePem(filePath string, der []byte, blockType string, private bool) error {
	var mode os.FileMode
	if private {
		mode = 0600
	} else {
		mode = 0644
	}
	out, err := AppFs.OpenFile(filePath, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, mode)

	if err != nil {
		return err
	}

	// defer close until after return, also check error
	defer func() {
		if err := out.Close(); err != nil {
			log.Fatalf("error closing file %s: %v", filePath, err)
		}
	}()
	return pem.Encode(out, &pem.Block{Type: blockType, Bytes: der})
}

// WritePrivateKey output key to filePath in PEM format
func WritePrivateKey(filePath string, key *rsa.PrivateKey) error {
	return writePem(
		filePath, x509.MarshalPKCS1PrivateKey(key), "RSA PRIVATE KEY", true)
}

// WriteCertificate outputs a certificate to filePath in PEM format
func WriteCertificate(filePath string, certificate []byte) error {
	return writePem(filePath, certificate, "CERTIFICATE", false)
}

func readPEM(filePath string) (*pem.Block, error) {
	data, err := afero.ReadFile(AppFs, filePath)
	if err != nil {
		return nil, err
	}
	block, _ := pem.Decode(data)
	if block == nil {
		return nil, errors.New(fmt.Sprintf("file not in PEM format: %s", filePath))
	}
	return block, nil
}

// ReadCertificatePEM reads a PEM formatted file in
func ReadCertificatePEM(filePath string) ([]byte, error) {
	block, err := readPEM(filePath)
	if err != nil {
		return nil, err
	}
	return block.Bytes, nil
}

// ReadPrivateKey parses an RSA private key in PEM format and returns the result.
func ReadPrivateKey(filePath string) (*rsa.PrivateKey, error) {
	block, err := readPEM(filePath)
	if err != nil {
		return nil, err
	}
	if block.Type != "RSA PRIVATE KEY" {
		return nil, errors.New("key is invalid")
	}
	return x509.ParsePKCS1PrivateKey(block.Bytes)
}

// InitStorage creates the storage directory, if dirPath does not already exist. This
// function also sets the storagePath global
func InitStorage(dirPath string) error {
	storagePath = dirPath
	return AppFs.MkdirAll(dirPath, 0700)
}

// StorePath appends filePath to storagePath
func StorePath(filePath string) string {
	return path.Join(storagePath, filePath)
}
