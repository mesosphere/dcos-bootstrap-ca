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
	"fmt"
	"github.com/spf13/cobra"
	"log"
	"os"
)

const VERSION = "0.1"
const versionFmt = "v" + VERSION

// rootCmd represents the base command when called without any subcommands
var rootCmd = &cobra.Command{
	Use: "dcoscertstrap",
	Short: "Simple program used to bootstrap TLS artifacts for " +
		"secure inter-cluster communications",
	Long: `This program is part of DC/OS and not intended for use
outside of this context`,
}

// Execute adds all child commands to the root command and sets flags appropriately.
// This is called by main.main(). It only needs to happen once to the rootCmd.
func Execute() {
	// enable --version flag
	rootCmd.SetVersionTemplate(fmt.Sprintln(versionFmt))
	rootCmd.Version = VERSION

	if err := rootCmd.Execute(); err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
}

func init() {
	rootCmd.PersistentFlags().StringP(
		"output-dir", "d", ".pki/", "Path to store program files")
}

func getString(cmd *cobra.Command, s string) string {
	v, err := cmd.Flags().GetString(s)
	if err != nil {
		log.Fatalf("%v\n", err)
	}
	return v
}

func getSlice(cmd *cobra.Command, s string) []string {
	v, err := cmd.Flags().GetStringSlice(s)
	if err != nil {
		log.Fatalf("%v\n", err)
	}
	return v
}
