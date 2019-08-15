package cmd

import (
	"bytes"
	"crypto/tls"
	"encoding/json"
	"encoding/pem"
	"github.com/mesosphere/dcos-bootstrap-ca/pkg/gen"
	"github.com/mesosphere/dcos-bootstrap-ca/pkg/server"
	"github.com/spf13/cobra"
	"log"
	"net/http"
	"net/url"
	"path"
)

var initCSRCmd = &cobra.Command{
	Use:   "csr",
	Short: "Request new certificate from CA service",
	RunE:  csrSign,
	Args:  cobra.MinimumNArgs(1),
}

func csrSign(cmd *cobra.Command, args []string) error {
	d, err := cmd.Flags().GetString("output-dir")

	if err != nil {
		return err
	}

	entity := args[0]
	entityKeyFile := entity + "-key.pem"
	entityCertFile := entity + "-cert.pem"

	baseURL := getString(cmd, "url")
	u, err := url.Parse(baseURL)
	if err != nil {
		log.Fatalf("error parsing url : %v", err)
	}
	u.Path = path.Join(u.Path, "csr", "v1", "sign")

	psk := getString(cmd, "psk")
	caFile := getString(cmd, "ca")

	if err := gen.InitStorage(d); err != nil {
		return err
	}

	clientKey, err := gen.ReadPrivateKey(gen.StorePath(entityKeyFile))
	if err != nil {

		log.Fatalf("could not read private key at %s : %v", gen.StorePath(entityKeyFile), err)
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

	b := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: csrBytes})
	j, err := json.Marshal(server.SignRequest{Psk: psk, Csr: string(b)})

	certPool, err := gen.GetCACertPool(caFile)
	if err != nil {
		log.Fatalf("error creating cert")
	}

	tlsConfig := &tls.Config{RootCAs: certPool}
	tr := &http.Transport{TLSClientConfig: tlsConfig}
	client := &http.Client{Transport: tr}

	resp, err := client.Post(u.String(), "application/json", bytes.NewReader(j))
	if err != nil {
		log.Fatalf("error talking to service : %v", err)
	}

	respJSON := &server.SignResponse{}
	decoder := json.NewDecoder(resp.Body)
	if err := decoder.Decode(respJSON); err != nil {
		buf := new(bytes.Buffer)
		buf.ReadFrom(decoder.Buffered())
		log.Fatalf("error parsing json : %v - %v", err, buf)
	}

	f, err := gen.AppFs.Create(gen.StorePath(entityCertFile))
	if err != nil {
		log.Fatalf("error creating file : %v", err)
	}
	_, err = f.Write([]byte(respJSON.Certificate))

	if err != nil {
		log.Fatalf("could not write signed certficate : %v", err)
	}
	log.Printf("wrote client certificate: %s", gen.StorePath(entityCertFile))
	return nil
}

func init() {
	rootCmd.AddCommand(initCSRCmd)
	initCSRCmd.Flags().String("url", "", "CA service URL. Start the service with URL")
	_ = initCSRCmd.MarkFlagRequired("url")
	initCSRCmd.Flags().String("psk", "", "The PSK that the server was started with")
	_ = initCSRCmd.MarkFlagRequired("psk")
	initCSRCmd.Flags().String("ca", "", "CA certificate used to verify CA service")
	initCSRCmd.Flags().String("common-name", "client", "Root certificate common name")
	initCSRCmd.Flags().String("country", "US", "Country name")
	initCSRCmd.Flags().String("state", "CA", "State or Provence")
	initCSRCmd.Flags().String("locality", "San Francisco", "Locality")
	initCSRCmd.Flags().String("organization", "Mesosphere Inc.", "organization")
	initCSRCmd.Flags().StringSlice("email-addresses", []string{"security@mesosphere.com"},
		"A list of administrative email addresses")
	initCSRCmd.Flags().StringSlice("sans", []string{}, "Subject Alternative Names")
}
