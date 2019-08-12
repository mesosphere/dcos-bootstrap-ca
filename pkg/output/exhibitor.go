package output

import (
	"crypto/x509"
	"fmt"
	"github.com/mesosphere/dcos-bootstrap-ca/pkg/gen"
	"github.com/pavel-v-chernykh/keystore-go"
	"github.com/spf13/afero"
	"io"
	"log"
	"os"
	"path"
	"time"
)

// AppFs afero file system abstraction
var AppFs = afero.NewOsFs()

func writeKeyStore(ks keystore.KeyStore, path, password string) error {
	o, err := AppFs.Create(path)
	if err != nil {
		return fmt.Errorf("error creating %s : %v", path, err)
	}
	defer o.Close()

	log.Printf("Creating %s", path)
	err = keystore.Encode(o, ks, []byte(password))
	if err != nil {
		return fmt.Errorf("error encoding keystore: %v", err)
	}
	return nil
}

func writeTrustStore(caPath, outputDir, password string) error {
	const filename = "truststore.jks"
	outputPath := path.Join(outputDir, filename)
	ks := keystore.KeyStore{}

	certBytes, err := gen.ReadCertificatePEM(caPath)
	if err != nil {
		return fmt.Errorf("error reading %s : %v", caPath, err)
	}

	ks["root-cert"] = &keystore.TrustedCertificateEntry{
		Entry: keystore.Entry{
			CreationDate: time.Now(),
		},
		Certificate: keystore.Certificate{
			Type:    "X509",
			Content: certBytes,
		},
	}

	return writeKeyStore(ks, outputPath, password)
}

func entityPaths(entity string) (string, string) {
	return gen.StorePath(entity + "-key.pem"), gen.StorePath(entity + "-cert.pem")
}

func writeEntityStore(alias, entity, ksPath, password string) error {
	ks := keystore.KeyStore{}
	keyPem, certPem := entityPaths(entity)
	pkcs1Key, err := gen.ReadPrivateKey(keyPem)
	if err != nil {
		return fmt.Errorf("error reading %s : %v", keyPem, err)
	}

	// Convert private key to PKCS #8
	key, err := x509.MarshalPKCS8PrivateKey(pkcs1Key)
	if err != nil {
		return fmt.Errorf("error marshelling PKCS private key : %v", err)
	}

	cert, err := gen.ReadCertificatePEM(certPem)
	if err != nil {
		return fmt.Errorf("error reading %s : %v", certPem, err)
	}

	ks[alias] = &keystore.PrivateKeyEntry{
		Entry: keystore.Entry{
			CreationDate: time.Now(),
		},
		PrivKey: key,
		CertChain: []keystore.Certificate{
			{
				Type:    "X509",
				Content: cert,
			},
		},
	}

	return writeKeyStore(ks, ksPath, password)
}

func writeServerStore(entity, outputDir, password string) error {
	const filename = "serverstore.jks"
	ksPath := path.Join(outputDir, filename)
	return writeEntityStore("server", entity, ksPath, password)
}

func writeClientStore(entity, outputDir, password string) error {
	const filename = "clientstore.jks"
	ksPath := path.Join(outputDir, filename)
	return writeEntityStore("client", entity, ksPath, password)
}

func copyFile(src, destDir string, mode os.FileMode) error {
	destPath := path.Join(destDir, path.Base(src))

	s, err := AppFs.Open(src)
	if err != nil {
		return err
	}

	defer s.Close()

	d, err := AppFs.OpenFile(destPath, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, mode)
	if err != nil {
		return err
	}
	defer d.Close()

	log.Printf("Copying %s to %s", src, destPath)
	_, err = io.Copy(d, s)
	if err != nil {
		return err
	}
	return nil
}

func copyEntities(destDir, clientEntity string) error {
	clientKey, clientCert := entityPaths(clientEntity)
	err := copyFile(clientKey, destDir, 0600)
	if err != nil {
		return err
	}
	return copyFile(clientCert, destDir, 0644)
}

// WriteArtifacts creates exhibitor TLS artifacts for DC/OS
func WriteArtifacts(path, caPath, serverEntity, clientEntity, password string) error {
	err := AppFs.MkdirAll(path, 0755)
	if err != nil {
		return fmt.Errorf("error creating %s : %v", path, err)
	}

	err = writeTrustStore(caPath, path, password)
	if err != nil {

		return err
	}

	err = writeServerStore(serverEntity, path, password)
	if err != nil {
		return err
	}

	err = writeClientStore(clientEntity, path, password)
	if err != nil {
		return err
	}

	err = copyEntities(path, clientEntity)
	if err != nil {
		return err
	}

	// Finally copy the CA certificate
	return copyFile(caPath, path, 0644)
}
