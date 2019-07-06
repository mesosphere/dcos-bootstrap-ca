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
	pKey, err := gen.GenerateRSAPrivateKey()
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

	// Here you will define your flags and configuration settings.

	// Cobra supports Persistent Flags which will work for this command
	// and all subcommands, e.g.:
	// initCACmd.PersistentFlags().String("foo", "", "A help for foo")

	// Cobra supports local flags which will only run when this command
	// is called directly, e.g.:
	// initCACmd.Flags().BoolP("toggle", "t", false, "Help message for toggle")

	initCACmd.Flags().StringP("common-name", "n", "ROOT", "Root certificate common name")
	initCACmd.Flags().StringP("country", "c", "", "Country name")
	initCACmd.Flags().StringP("state", "s", "", "State or Provence")
	initCACmd.Flags().StringP("locality", "l", "", "Locality")
	initCACmd.Flags().StringP("organization", "o", "", "organization")
	initCACmd.Flags().StringSlice("sans", []string{}, "Subject Alternative Names")
}
