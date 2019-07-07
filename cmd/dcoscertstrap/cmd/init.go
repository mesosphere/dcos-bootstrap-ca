/*
Copyright © 2019 security@mesosphere.com

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
	"encoding/pem"
	"fmt"
	"log"

	"github.com/jr0d/dcoscertstrap/pkg/gen"
	"github.com/spf13/cobra"
)

// initCmd represents the init command
var initCmd = &cobra.Command{
	Use:   "init",
	Short: "A brief description of your command",
	Long: `A longer description that spans multiple lines and likely contains examples
and usage of using your command. For example:

Cobra is a CLI library for Go that empowers applications.
This application is a tool to generate the needed files
to quickly create a Cobra application.`,
	Run: generateCertificate,
}

func init() {
	rootCmd.AddCommand(initCmd)

	// Here you will define your flags and configuration settings.

	// Cobra supports Persistent Flags which will work for this command
	// and all subcommands, e.g.:
	// initCmd.PersistentFlags().String("foo", "", "A help for foo")

	// Cobra supports local flags which will only run when this command
	// is called directly, e.g.:
	// initCmd.Flags().BoolP("toggle", "t", false, "Help message for toggle")
}

func generateCertificate(cmd *cobra.Command, args []string) {
	pKey, _ := rsa.GenerateKey(rand.Reader, 2048)
	config := gen.MakeCertificateConfig(
		"ROOT",
		"US",
		"TX",
		"San Antonio",
		"Mesosphere Inc.",
		[]string{"localhost", "127.0.0.1"},
		true)

	rootCert, err := gen.GenerateCertificate(config, nil, pKey)
	if err != nil {
		log.Fatalf("Wow: %v", err)
	}
	encoded := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: rootCert})
	fmt.Printf("%s\n", string(encoded))
}
