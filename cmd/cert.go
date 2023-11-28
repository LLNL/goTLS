// Copyright © 2019 Lawrence Livermore National Security, LLC
// SPDX-License-Identifier: MIT
// See top-level LICENSE file for details.

package cmd

import (
	"bufio"
	"fmt"
	"os"
	"strings"

	"github.com/bgentry/speakeasy"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"

	"github.com/llnl/gotls/crypto"
	"github.com/llnl/gotls/http"
)

func getCertConfig(args []string) *http.CertConfig {
	if !viper.IsSet("adcs-url") {
		fmt.Fprintf(os.Stderr, "error: adcs-url is not set\n")
		os.Exit(1)
	}
	adcsUrl := viper.GetString("adcs-url")
	if !viper.IsSet("oid-template") {
		fmt.Fprintf(os.Stderr, "error: oid-template is not set\n")
		os.Exit(1)
	}
	oidTemplate := viper.GetString("oid-template")

	return &http.CertConfig{
		AdcsUrl:     adcsUrl,
		OidTemplate: oidTemplate,
	}
}

// certCmd represents the cert command
var certCmd = &cobra.Command{
	Use:   "cert",
	Short: "Generate a certificate signed by the configured authority",
	Long: `Contacts the given signing authority and obtains a signed TLS
certificate corresponding to the given CSR`,
	Args: cobra.MinimumNArgs(1),
}

var adcsCmd = &cobra.Command{
	Use:   "adcs filename.csr",
	Short: "Obtains certificate from Microsoft AD Certificate Services",
	Long:  `Obtains a signed certificate from Microsoft AD Certificate Services`,
	Args:  cobra.ExactArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		adcs(cmd, args)
	},
}

func adcs(cmd *cobra.Command, args []string) {
	// load config
	config := getCertConfig(args)

	// get CSR filename
	csrFileName := args[0]

	// read in CSR
	var csr string
	if _, err := os.Stat(csrFileName); err != nil {
		fmt.Fprintf(os.Stderr, "error accessing CSR file: %s\n", err)
		os.Exit(1)
	} else { // CSR file exists
		csrBytes, err := os.ReadFile(csrFileName)
		if err != nil {
			fmt.Fprintf(os.Stderr, "error reading CSR file: %s\n", err)
			os.Exit(1)
		}
		csr = string(csrBytes)
	}

	// get username
	fmt.Printf("Authenticate to AD Certificate Services:\n  username: ")
	scanner := bufio.NewScanner(os.Stdin)
	scanner.Scan()
	user := scanner.Text()

	// get password
	pass, err := speakeasy.Ask("  password: ")
	if err != nil {
		fmt.Fprintf(os.Stderr, "error getting password: %s\n", err)
		os.Exit(1)
	}

	// get cert
	cert, err := http.PostAdcsRequest(user, pass, csr, config)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error getting cert: %s\n", err)
		os.Exit(1)
	}

	//TODO: move existing cert to .old?

	// write cert
	certFileName := fmt.Sprintf("%s.crt", strings.TrimSuffix(csrFileName, ".csr"))
	if err = crypto.WriteCert(certFileName, cert); err != nil {
		fmt.Fprintf(os.Stderr, "error writing cert: %s\n", err)
		os.Exit(1)
	}
}

func init() {
	RootCmd.AddCommand(certCmd)

	adcsCmd.Flags().String("adcs-url", "", "AD Certificate Services endpoint url")
	adcsCmd.Flags().String("oid-template", "", "OID string usually selected in the ADCS template dropdown")

	viper.BindPFlag("adcs-url", adcsCmd.Flags().Lookup("adcs-url"))
	viper.BindPFlag("oid-template", adcsCmd.Flags().Lookup("oid-template"))

	// add adcs sub-command
	certCmd.AddCommand(adcsCmd)
}
