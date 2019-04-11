// Copyright © 2019 Lawrence Livermore National Security
// See LICENSE file

package cmd

import (
	"fmt"
	"os"
	"strings"

	"github.com/spf13/cobra"
	"github.com/spf13/viper"

	"github.com/llnl/gotls/crypto"
)

var cn string
var dns []string
var c string
var st string
var l string
var o string
var ou string
var email string

// csrCmd represents the csr command
var csrCmd = &cobra.Command{
	Use: "csr primary-hostname.fq.dn [additional-hostname(s)]",
	Short: "Generate a Certificate Signing Request",
	Long: `Generate a Certificate Signing Request given a number of hostname(s).
If a private key matching the given primary hostname exists in the current
directory it will be used, otherwise a new key will be created.`,
	Args: cobra.MinimumNArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		// load flag variables
		c = viper.GetString("c")
		st = viper.GetString("st")
		l = viper.GetString("l")
		o = viper.GetString("o")
		ou = viper.GetString("ou")
		email = viper.GetString("email")

		// parse dns args
		dns = make([]string, 0, len(args))
		for i, arg := range args {
			if i == 0 {
				cn = args[0]
			}
			dns = append(dns, arg)
		}

		//TODO: test for non-empty values
		//TODO: test args for IP, don't assume DNS

		fmt.Printf(`Generating %s.csr with values:
CN: %s
SAN: %s
C: %s
ST: %s
L: %s
O: %s
OU: %s
email: %s

`, cn, cn, strings.Join(dns, " "), c, st, l, o, ou, email)

		keyFileName := fmt.Sprintf("%s.key", cn)
		csrFileName := fmt.Sprintf("%s.csr", cn)

		// get key
		key, err := crypto.GetKey(keyFileName, rsaSize)
		if err != nil {
			fmt.Printf("Error getting private key: %s", err)
			os.Exit(1)
		}

		if _, err := crypto.GenerateCsr(csrFileName, key, cn, dns, c, st, l, o, ou, email); err != nil {
			fmt.Printf("Error generating CSR: %s", err)
			os.Exit(1)
		} else {
			fmt.Printf("Wrote csr to %s\n", csrFileName)
		}
	},
}

func init() {
	RootCmd.AddCommand(csrCmd)

	// define flags
	csrCmd.Flags().StringVarP(&email, "email", "e", "", "Email address to submit")
	csrCmd.Flags().StringVarP(&c, "c", "c", "", "Country field for CSR")
	csrCmd.Flags().StringVarP(&st, "st", "", "", "Province or state field for CSR")
	csrCmd.Flags().StringVarP(&l, "l", "l", "", "Locality or city field for CSR")
	csrCmd.Flags().StringVarP(&o, "o", "o", "", "Organization field for CSR")
	csrCmd.Flags().StringVarP(&ou, "ou", "", "", "Organization Unit field for CSR")

	// bind flags to conf file values (appears to be case-insensitive)
	viper.BindPFlag("c", csrCmd.Flags().Lookup("c"))
	viper.BindPFlag("st", csrCmd.Flags().Lookup("st"))
	viper.BindPFlag("l", csrCmd.Flags().Lookup("l"))
	viper.BindPFlag("o", csrCmd.Flags().Lookup("o"))
	viper.BindPFlag("ou", csrCmd.Flags().Lookup("ou"))
	viper.BindPFlag("email", csrCmd.Flags().Lookup("email"))
}
