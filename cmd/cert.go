// Copyright © 2019 Lawrence Livermore National Security
// See LICENSE file

package cmd

import (
	"bufio"
	"fmt"
	"io/ioutil"
	"os"

	"github.com/bgentry/speakeasy"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"

	"gotls/http"
)

var adcsUrl string

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

		if err := http.PostAdcsRequest(adcsUrl, user, pass, csr); err != nil {
			fmt.Printf("Error getting cert: %s\n", err)
			os.Exit(1)
		}
	},
}

func init() {
	rootCmd.AddCommand(certCmd)

	// add adcs sub-command
	certCmd.AddCommand(adcsCmd)

	adcsCmd.Flags().StringVarP(&email, "adcs-url", "", "", "AD Certificate Services endpoint url")
	viper.BindPFlag("adcs-url", adcsCmd.Flags().Lookup("adcs-url"))
	//TODO: adcsCmd.MarkFlagRequired("adcs-url") but allow for setting from viper
}
