// Copyright © 2019 Lawrence Livermore National Security
// See LICENSE file

package cmd

import (
	"bufio"
	"fmt"
	"io/ioutil"
	"os"
	"strings"

	"github.com/bgentry/speakeasy"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"

	"github.com/llnl/gotls/http"
	"github.com/llnl/gotls/crypto"
)

var adcsUrl string
var oidTemplate string

// certCmd represents the cert command
var certCmd = &cobra.Command{
	Use:   "cert",
	Short: "Generate a certificate signed by the configured authority",
	Long: `Contacts the given signing authority and obtains a signed TLS
certificate corresponding to the given CSR`,
	Args: cobra.MinimumNArgs(1),
}

var adcsCmd = &cobra.Command{
	Use:   "adcs",
	Short: "Obtains certificate from Microsoft AD Certificate Services",
	Long: `Obtains a signed certificate from Microsoft AD Certificate Services`,
	Args: cobra.ExactArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		// get ADCS endpoint url
		adcsUrl = viper.GetString("adcs-url")
		oidTemplate = viper.GetString("oid-template")

		// get CSR filename
		csrFileName := args[0]

		// read in CSR
		var csr string
		if _, err := os.Stat(csrFileName); err != nil {
			fmt.Printf("Error accessing CSR file: %s\n", err)
			os.Exit(1)
		} else { // CSR file exists
			csrBytes, err := ioutil.ReadFile(csrFileName)
			if err != nil {
				fmt.Printf("Error reading CSR: %s\n", err)
				os.Exit(1)
			}
			csr = string(csrBytes)
		}

		// get user name
		fmt.Printf("Authenticate to AD Certificate Services:\nUsername: ")
		scanner := bufio.NewScanner(os.Stdin)
		scanner.Scan()
		user := scanner.Text()

		// get password
		pass, err := speakeasy.Ask("password: ")
		if err != nil {
			fmt.Printf("Error getting password: %s", err)
			os.Exit(1)
		}

		// get cert
		cert, err := http.PostAdcsRequest(adcsUrl, user, pass, csr, oidTemplate)
		if err != nil {
			fmt.Printf("Error getting cert: %s\n", err)
			os.Exit(1)
		}

		//TODO: move existing cert to .old?

		// write cert
		certFileName := fmt.Sprintf("%s.crt", strings.TrimSuffix(csrFileName, ".csr"))
		if err = crypto.WriteCert(certFileName, cert); err != nil {
			fmt.Printf("Error writing cert: %s\n", err)
			os.Exit(1)
		}
	},
}

func init() {
	RootCmd.AddCommand(certCmd)

	// add adcs sub-command
	certCmd.AddCommand(adcsCmd)

	adcsCmd.Flags().StringVarP(&adcsUrl, "adcs-url", "", "", "AD Certificate Services endpoint url")
	adcsCmd.Flags().StringVarP(&oidTemplate, "oid-template", "", "", "OID string usually selected in the ADCS template dropdown")

	viper.BindPFlag("adcs-url", adcsCmd.Flags().Lookup("adcs-url"))
	viper.BindPFlag("oid-template", adcsCmd.Flags().Lookup("oid-template"))

	//TODO: adcsCmd.MarkFlagRequired("url") and "oid-template" but allow for setting from viper
}
