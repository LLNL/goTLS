// Copyright © 2019 Lawrence Livermore National Security, LLC
// SPDX-License-Identifier: MIT
// See top-level LICENSE file for details.

package cmd

import (
	"crypto/x509"
	"fmt"
	"log/slog"
	"net"
	"os"
	"strings"

	"github.com/spf13/cobra"
	"github.com/spf13/viper"

	"github.com/llnl/gotls/crypto"
	"github.com/llnl/gotls/http"
)

var keyFilename, outputFilename string

// csrCmd represents the csr command
var csrCmd = &cobra.Command{
	Use:   "csr [Flags] primary-hostname.fq.dn [additional-hostname-or-IP(s)]",
	Short: "Generate a Certificate Signing Request",
	Long: `Generate a Certificate Signing Request given hostname(s) or ip(s).
The filename of the private key to derive the CSR from can be provided to the
--key parameter or will be constructed from the first argument
(primary-hostname.fq.dn.key). If that filename does not exist in the current
directory, a new RSA private key will be created. For more control over the
key parameters, use the gotls key command.`,
	Args:                  cobra.MinimumNArgs(1),
	DisableFlagsInUseLine: true,
	Run: func(cmd *cobra.Command, args []string) {
		// load flag variables
		config := getCsrConfig(args)

		// load rsaSize from config
		if viper.IsSet("rsa-size") {
			rsaSize = viper.GetInt("rsa-size")
		}

		// convert IPs to string represenatation
		ips := make([]string, 0, len(config.IP))
		for _, ip := range config.IP {
			ips = append(ips, ip.String())
		}

		slog.Debug("generating csr",
			"CN", config.CN,
			"C", config.C,
			"ST", config.ST,
			"L", config.L,
			"O", config.O,
			"OU", config.OU,
			"Email", config.Email,
			"DNS", strings.Join(config.DNS, ","),
			"IP", strings.Join(ips, ","),
		)

		if keyFilename == "" {
			keyFilename = fmt.Sprintf("%s.key", config.CN)
		}
		if outputFilename == "" {
			outputFilename = fmt.Sprintf("%s.csr", config.CN)
		}

		// get key
		var key any
		if _, err := os.Stat(keyFilename); err == nil { // key exists
			key = LoadKey(keyFilename)
		} else { // key does not exist, create default key (RSA 2048 PKCS#1)
			key = CreateKey(&crypto.KeyRequest{
				Filename:  keyFilename,
				Type:      x509.RSA,
				Container: crypto.PKCS1,
				RsaSize:   rsaSize,
			})
		}

		if _, err := crypto.GenerateCsr(outputFilename, key, config.CN, config.C, config.ST, config.L, config.O,
			config.OU, config.Email, config.DNS, config.IP); err != nil {
			slog.Error("could not generate csr", slog.Any("error", err))
			os.Exit(1)
		} else {
			slog.Info("wrote csr", "filename", outputFilename)
		}
	},
}

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
				slog.Error("could not generate csr: invalid IP address", "ip", arg)
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

func LoadKey(filename string) (key any) {
	slog.Debug("loading existing private key", "filename", outputFilename)

	keyRequest := &crypto.KeyRequest{
		Filename: filename,
	}

	// load key
	key, err := crypto.GetKey(keyRequest)
	if err != nil {
		slog.Error("could not load key", "filename", filename, slog.Any("error", err))
		os.Exit(1)
	}

	slog.Info("private key found",
		"filename", keyRequest.Filename,
		"type", keyRequest.Type.String(),
		"container", keyRequest.Container.String(),
	)

	return key
}

func initCsr() {
	// define flags
	csrCmd.Flags().StringP("email", "e", "", "Email address field for CSR")
	csrCmd.Flags().String("C", "", "Country field for CSR")
	csrCmd.Flags().String("ST", "", "Province or state field for CSR")
	csrCmd.Flags().String("L", "", "Locality or city field for CSR")
	csrCmd.Flags().String("O", "", "Organization field for CSR")
	csrCmd.Flags().String("OU", "", "Organization Unit field for CSR")
	csrCmd.Flags().StringVarP(&keyFilename, "key", "k", "", "Filename containing private key (default is primary-hostname.fq.dn.key)")
	csrCmd.Flags().StringVarP(&outputFilename, "output", "o", "", "Filename for writing CSR (default is primary-hostname.fq.dn.csr)")

	// bind flags to conf file values
	viper.BindPFlag("c", csrCmd.Flags().Lookup("C"))
	viper.BindPFlag("st", csrCmd.Flags().Lookup("ST"))
	viper.BindPFlag("l", csrCmd.Flags().Lookup("L"))
	viper.BindPFlag("o", csrCmd.Flags().Lookup("O"))
	viper.BindPFlag("ou", csrCmd.Flags().Lookup("OU"))
	viper.BindPFlag("email", csrCmd.Flags().Lookup("email"))

	RootCmd.AddCommand(csrCmd)
}
