// Copyright © 2019 Lawrence Livermore National Security, LLC
// SPDX-License-Identifier: MIT
// See top-level LICENSE file for details.

package cmd

import (
	"fmt"
	"os"
	"strings"

	"github.com/spf13/cobra"
	"github.com/spf13/viper"

	"github.com/llnl/gotls/crypto"
)

type CsrConfig struct {
	c     string
	st    string
	l     string
	o     string
	ou    string
	email string
	cn    string
	dns   []string
}

func getCsrConfig(args []string) *CsrConfig {
	c := viper.GetString("c")
	st := viper.GetString("st")
	l := viper.GetString("l")
	o := viper.GetString("o")
	ou := viper.GetString("ou")
	email := viper.GetString("email")
	var cn string

	// parse dns args
	dns := make([]string, 0, len(args))
	for i, arg := range args {
		if i == 0 {
			cn = args[0]
		}
		dns = append(dns, arg)
	}

	//TODO: test args for IP, don't assume DNS

	return &CsrConfig{
		c:     c,
		st:    st,
		l:     l,
		o:     o,
		ou:    ou,
		email: email,
		cn:    cn,
		dns:   dns,
	}
}

// csrCmd represents the csr command
var csrCmd = &cobra.Command{
	Use:   "csr primary-hostname.fq.dn [additional-hostname(s)]",
	Short: "Generate a Certificate Signing Request",
	Long: `Generate a Certificate Signing Request given a number of hostname(s).
If a private key matching the given primary hostname exists in the current
directory it will be used, otherwise a new key will be created.`,
	Args: cobra.MinimumNArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		csr(cmd, args)
	},
}

func csr(cmd *cobra.Command, args []string) {
	// load flag variables
	config := getCsrConfig(args)

	fmt.Printf(`Generating %s.csr with values:
CN: %s
SAN: %s
C: %s
ST: %s
L: %s
O: %s
OU: %s
email: %s

`, config.cn, config.cn, strings.Join(config.dns, " "), config.c, config.st, config.l, config.o, config.ou, config.email)

	keyFileName := fmt.Sprintf("%s.key", config.cn)
	csrFileName := fmt.Sprintf("%s.csr", config.cn)

	// get key
	key, err := crypto.GetKey(keyFileName, rsaSize)
	if err != nil {
		fmt.Printf("error getting private key: %s\n", err)
		os.Exit(1)
	}

	if _, err := crypto.GenerateCsr(csrFileName, key, config.cn, config.dns, config.c, config.st, config.l, config.o,
		config.ou, config.email); err != nil {
		fmt.Printf("error generating CSR: %s\n", err)
		os.Exit(1)
	} else {
		fmt.Printf("wrote csr to %s\n", csrFileName)
	}
}

func initCsr() {
	// define flags
	csrCmd.Flags().StringP("email", "e", "", "Email address to submit")
	csrCmd.Flags().StringP("c", "c", "", "Country field for CSR")
	csrCmd.Flags().StringP("st", "", "", "Province or state field for CSR")
	csrCmd.Flags().StringP("l", "l", "", "Locality or city field for CSR")
	csrCmd.Flags().StringP("o", "o", "", "Organization field for CSR")
	csrCmd.Flags().StringP("ou", "", "", "Organization Unit field for CSR")
	csrCmd.Flags().IntVarP(&rsaSize, "rsa-size", "", 2048, "RSA key size to use")

	// bind flags to conf file values
	viper.BindPFlag("c", csrCmd.Flags().Lookup("c"))
	viper.BindPFlag("st", csrCmd.Flags().Lookup("st"))
	viper.BindPFlag("l", csrCmd.Flags().Lookup("l"))
	viper.BindPFlag("o", csrCmd.Flags().Lookup("o"))
	viper.BindPFlag("ou", csrCmd.Flags().Lookup("ou"))
	viper.BindPFlag("email", csrCmd.Flags().Lookup("email"))

	RootCmd.AddCommand(csrCmd)
}
