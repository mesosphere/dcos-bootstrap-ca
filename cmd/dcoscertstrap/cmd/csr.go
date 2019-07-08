package cmd

import (
	"crypto/x509"
	"fmt"
	"github.com/jr0d/dcoscertstrap/pkg/gen"
	"github.com/spf13/cobra"
	"log"
)

var initCSRCmd = &cobra.Command{
	Use:   "csr",
	Short: "Request new certificate from CA service",
	RunE:  csrSign,
}

func csrSign(cmd *cobra.Command, args []string) error {
	// Temporary local signing test
	var rootKeyFile = "root-key.pem"
	var rootCAFaile = "root-ca.pem"
	var clientKeyFile = "client-key.pem"

	d, err := cmd.Flags().GetString("output-dir")
	if err != nil {
		return err
	}

	if err := gen.InitStorage(d); err != nil {
		return err
	}

	clientKey, err := gen.ReadPrivateKey(gen.StorePath(clientKeyFile))
	if err != nil {
		log.Fatalf("could not read private key at %s : %v", gen.StorePath(clientKeyFile), err)
	}

	config := gen.MakeCSRConfig(
		getString(cmd, "common-name"),
		getString(cmd, "country"),
		getString(cmd, "state"),
		getString(cmd, "locality"),
		getString(cmd, "organization"),
		getSlice(cmd, "sans"),
		getSlice(cmd, "email-addresses"),
	)

	csrBytes, err := gen.GenerateCSR(config, clientKey)
	if err != nil {
		log.Fatalf("error generating CSR: %v", err)
	}

	csr, err := x509.ParseCertificateRequest(csrBytes)
	if err != nil {
		log.Fatalf("error parsing CSR: %v", csr)
	}
	certBytes, err := gen.ReadCertificatePEM(gen.StorePath(rootCAFaile))
	if err != nil {
		log.Fatalf("Error reading certificate: %v", err)
	}
	log.Printf("%x\n", certBytes)
	cert, err := x509.ParseCertificate(certBytes)
	if err != nil {
		log.Fatalf("error parsing certificate: %v", err)
	}
	key, err := gen.ReadPrivateKey(gen.StorePath(rootKeyFile))
	if err != nil {
		log.Fatalf("error reading private key: %v", err)
	}

	fmt.Printf("KEY: %v\n", key)
	signedCert, err := gen.Sign(*csr, *cert, *key)
	if err != nil {
		log.Fatalf("error signing certificate: %v", err)
	}

	_ = gen.WriteCertificate("/tmp/signed.pem", signedCert)
	return nil
}

func init() {
	rootCmd.AddCommand(initCSRCmd)
	initCSRCmd.Flags().String("url", "", "CA service URL. Start the service with URL")
	_ = initCSRCmd.MarkFlagRequired("url")
	initCSRCmd.Flags().String("psk", "", "The PSK that the server was started with")
	_ = initCSRCmd.MarkFlagRequired("psk")
	initCSRCmd.Flags().String("CAFile", "", "CA certificate used to verify CA service")
	initCSRCmd.Flags().String("common-name", "ROOT", "Root certificate common name")
	initCSRCmd.Flags().String("country", "", "Country name")
	initCSRCmd.Flags().String("state", "", "State or Provence")
	initCSRCmd.Flags().String("locality", "", "Locality")
	initCSRCmd.Flags().String("organization", "", "organization")
	initCSRCmd.Flags().StringSliceP("email-addresses", "e", []string{},
		"A list of administrative email addresses")
	initCSRCmd.Flags().StringSlice("sans", []string{}, "Subject Alternative Names")
}
