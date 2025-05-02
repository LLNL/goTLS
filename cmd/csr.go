// Copyright © 2019 Lawrence Livermore National Security, LLC
// SPDX-License-Identifier: MIT
// See top-level LICENSE file for details.

package cmd

import (
	"fmt"
	"net"
	"os"
	"strings"

	"github.com/spf13/cobra"
	"github.com/spf13/viper"

	"github.com/llnl/gotls/crypto"
	"github.com/llnl/gotls/http"
)

func getCsrConfig(args []string) *http.CsrConfig {
	var cn string

	c := viper.GetString("c")
	st := viper.GetString("st")
	l := viper.GetString("l")
	o := viper.GetString("o")
	ou := viper.GetString("ou")
	email := viper.GetString("email")

	// parse remaining args as SAN entries in this order:
	//    if argument has a prefix of ip: or dns:, strip the prefix and parse as such.
	//    Without a prefix, try to parse as an IP first, then failing that, assume a dns name.
	dns := make([]string, 0, len(args))
	ips := make([]net.IP, 0, len(args))
	for i, arg := range args {
		if i == 0 {
			cn = arg
		}
		arg = strings.ToLower(arg)
		if strings.HasPrefix(arg, "ip:") {
			if ip := net.ParseIP(strings.TrimPrefix(arg, "ip:")); ip != nil {
				ips = append(ips, ip)
			} else {
				fmt.Printf("error generating csr: Invalid IP address %s\n", arg)
				os.Exit(1)
			}
		} else if strings.HasPrefix(arg, "dns:") {
			dns = append(dns, strings.TrimPrefix(arg, "dns:"))
		} else { // no prefix
			if ip := net.ParseIP(arg); ip != nil { // try ip first
				ips = append(ips, ip)
			} else { // assume dns entry
				dns = append(dns, arg)
			}
		}
	}

	return &http.CsrConfig{
		CN:    cn,
		C:     c,
		ST:    st,
		L:     l,
		O:     o,
		OU:    ou,
		Email: email,
		DNS:   dns,
		IP:    ips,
	}
}

// csrCmd represents the csr command
var csrCmd = &cobra.Command{
	Use:   "csr primary-hostname.fq.dn [additional-hostname-or-IP(s)]",
	Short: "Generate a Certificate Signing Request",
	Long: `Generate a Certificate Signing Request given a number of hostname(s)/ip(s).
If a private key matching the given primary hostname (first argument) exists in the current
directory it will be used, otherwise a new key will be created.`,
	Args: cobra.MinimumNArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		csr(cmd, args)
	},
}

func csr(cmd *cobra.Command, args []string) {
	// load flag variables
	config := getCsrConfig(args)

	// convert IPs to string represenatation
	ips := make([]string, 0, len(config.IP))
	for _, ip := range config.IP {
		ips = append(ips, ip.String())
	}

	if verbose {
		fmt.Printf(`Generating %s.csr with values:
CN: %s
C: %s
ST: %s
L: %s
O: %s
OU: %s
Email: %s
DNS: %s
IP: %s
`, config.CN, config.CN, config.C, config.ST, config.L, config.O, config.OU, config.Email, strings.Join(config.DNS, ","),
			strings.Join(ips, ","))
	}
	keyFileName := fmt.Sprintf("%s.key", config.CN)
	csrFileName := fmt.Sprintf("%s.csr", config.CN)

	// get key
	key, err := crypto.GetKey(keyFileName, rsaSize, verbose)
	if err != nil {
		fmt.Printf("error getting private key: %s\n", err)
		os.Exit(1)
	}

	if _, err := crypto.GenerateCsr(csrFileName, key, config.CN, config.C, config.ST, config.L, config.O, config.OU,
		config.Email, config.DNS, config.IP); err != nil {
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
