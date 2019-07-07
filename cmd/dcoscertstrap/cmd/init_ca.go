/*
Copyright © 2019 NAME HERE <EMAIL ADDRESS>

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package cmd

import (
	"crypto/rand"
	"crypto/rsa"
	"github.com/jr0d/dcoscertstrap/pkg/gen"
	"github.com/spf13/cobra"
	"log"
)

// initCACmd represents the initCA command
var initCACmd = &cobra.Command{
	Use:   "init-ca",
	Short: "Initialize a new certificate authority",
	RunE:  initializeCA,
}

func initializeCA(cmd *cobra.Command, args []string) error {
	var keyFile = "root-key.pem"
	var certFile = "root-ca.pem"

	d, err := cmd.Flags().GetString("output-dir")
	if err != nil {
		return err
	}
	log.Printf("Initilizing new CA at %s\n", d)
	if err := gen.InitStorage(d); err != nil {
		return err
	}

	log.Printf("Generating private key\n")
	pKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return err
	}

	config := gen.MakeCertificateConfig(
		getString(cmd, "common-name"),
		getString(cmd, "country"),
		getString(cmd, "state"),
		getString(cmd, "locality"),
		getString(cmd, "organization"),
		getSlice(cmd, "sans"),
		true,
	)

	cert, err := gen.GenerateCertificate(config, nil, pKey)
	if err != nil {
		return err
	}
	if err := gen.WritePrivateKey(gen.StorePath(keyFile), pKey); err != nil {
		return err
	}
	if err := gen.WriteCertificate(gen.StorePath(certFile), cert); err != nil {
		return err
	}

	return nil
}

func init() {
	rootCmd.AddCommand(initCACmd)
	initCACmd.Flags().StringP("common-name", "n", "ROOT", "Root certificate common name")
	initCACmd.Flags().StringP("country", "c", "", "Country name")
	initCACmd.Flags().StringP("state", "s", "", "State or Provence")
	initCACmd.Flags().StringP("locality", "l", "", "Locality")
	initCACmd.Flags().StringP("organization", "o", "", "organization")
	initCACmd.Flags().StringSlice("sans", []string{}, "Subject Alternative Names")
}
