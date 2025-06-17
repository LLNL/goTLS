// Copyright © 2019 Lawrence Livermore National Security, LLC
// SPDX-License-Identifier: MIT
// See top-level LICENSE file for details.

package cmd

import (
	"bufio"
	"fmt"
	"log/slog"
	"os"
	"strings"

	"github.com/bgentry/speakeasy"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"

	"github.com/llnl/gotls/crypto"
	"github.com/llnl/gotls/http"
)

// certCmd represents the cert command
var certCmd = &cobra.Command{
	Use:   "cert",
	Short: "Obtain certificates signed by the configured authority",
	Long: `Contacts the given signing authority and obtains a signed TLS
certificate corresponding to the given CSR`,
	Args: cobra.MinimumNArgs(1),
}

func getCertConfig(args []string) *http.CertConfig {
	var adcsAuthKrb5conf, adcsAuthUser, adcsAuthRealm, adcsAuthKeytab string
	var adcsAuthKdcs []string

	if !viper.IsSet("adcs-url") {
		slog.Error("adcs-url is not set")
		os.Exit(1)
	}
	adcsUrl := viper.GetString("adcs-url")

	if !viper.IsSet("oid-template") {
		slog.Error("oid-template is not set")
		os.Exit(1)
	}
	oidTemplate := viper.GetString("oid-template")

	if !viper.IsSet("adcs-auth.method") {
		slog.Error("adcs-auth.method is not set")
		os.Exit(1)
	}
	adcsAuthMethod := strings.ToLower(viper.GetString("adcs-auth.method"))
	if _, ok := http.AuthMethodMap[adcsAuthMethod]; !ok {
		slog.Error("invalid auth method", "adcs-auth.method", adcsAuthMethod)
		os.Exit(1)
	}

	if viper.IsSet("adcs-auth.user") {
		adcsAuthUser = viper.GetString("adcs-auth.user")
	}

	if adcsAuthMethod == "kerberos" {
		if viper.IsSet("adcs-auth.krb5conf") {
			adcsAuthKrb5conf = viper.GetString("adcs-auth.krb5conf")
		} else {
			if !viper.IsSet("adcs-auth.realm") && !viper.IsSet("adcs-auth.kdcs") {
				slog.Error("auth method kerberos requires either krb5conf or both realm and kdcs to be set")
				os.Exit(1)
			}
		}
		if viper.IsSet("adcs-auth.realm") {
			adcsAuthRealm = viper.GetString("adcs-auth.realm")
		}
		if viper.IsSet("adcs-auth.kdcs") {
			adcsAuthKdcs = viper.GetStringSlice("adcs-auth.kdcs")
		}
		if viper.IsSet("adcs-auth.keytab") {
			adcsAuthKeytab = viper.GetString("adcs-auth.keytab")
		}
	}

	certConfig := &http.CertConfig{
		AdcsUrl:          adcsUrl,
		OidTemplate:      oidTemplate,
		AdcsAuthKrb5conf: adcsAuthKrb5conf,
		AdcsAuthUser:     adcsAuthUser,
		AdcsAuthRealm:    adcsAuthRealm,
		AdcsAuthKeytab:   adcsAuthKeytab,
		AdcsAuthKdcs:     adcsAuthKdcs,
	}
	certConfig.SetAuthMethodString(adcsAuthMethod)

	return certConfig
}

var adcsCmd = &cobra.Command{
	Use:   "adcs filename.csr [additional.csr]",
	Short: "Obtains certificates from Microsoft ADCS",
	Long:  `Obtains signed certificates from Microsoft AD Certificate Services`,
	Args:  cobra.MinimumNArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		adcs(cmd, args)
	},
}

func adcs(cmd *cobra.Command, args []string) {
	var csrs []http.CsrRequest
	var user, pass string
	var err error

	// load config
	config := getCertConfig(args)

	// read CSR files
	for _, csrFilename := range args {
		// read in CSR
		if _, err := os.Stat(csrFilename); err != nil {
			slog.Error("could not access CSR file", "filename", csrFilename, slog.Any("error", err))
			os.Exit(1)
		} else { // CSR file exists
			csrBytes, err := os.ReadFile(csrFilename)
			if err != nil {
				slog.Error("could not read CSR file", "filename", csrFilename, slog.Any("error", err))
				os.Exit(1)
			}
			csrs = append(csrs, http.CsrRequest{
				Content:  csrBytes,
				Filename: csrFilename,
			})
			slog.Debug("read csr", "filename", csrFilename)
		}
	}

	// get username
	if config.AdcsAuthUser != "" {
		user = config.AdcsAuthUser
	} else {
		//TODO: do we want to try the current user if user is not set?

		fmt.Printf("Username for AD Certificate Services: ")
		scanner := bufio.NewScanner(os.Stdin)
		scanner.Scan()
		user = scanner.Text()
	}

	// get password
	if config.AdcsAuthKeytab == "" {
		pass, err = speakeasy.Ask("Password for AD Certificate Services: ")
		if err != nil {
			slog.Error("could not get password", slog.Any("error", err))
			os.Exit(1)
		}
	}

	// get certs
	certs, errors := http.PostAdcsRequest(user, pass, csrs, config)

	// write successful certs
	for _, cert := range certs {
		//TODO: move existing cert to .old?

		// write cert
		if err := crypto.WriteCert(cert.Filename, cert.Cert); err != nil {
			slog.Error("could not write certificate", "filename", cert.Filename, slog.Any("error", err))
			os.Exit(1)
		} else {
			slog.Info("wrote certificate", "filename", cert.Filename)
		}
	}

	// handle errors
	if len(errors) > 0 {
		for _, err := range errors {
			slog.Error("could not obtain certificate", slog.Any("error", err))
		}
		os.Exit(1)
	}
}

func initCert() {
	RootCmd.AddCommand(certCmd)

	adcsCmd.Flags().String("adcs-url", "", "AD Certificate Services endpoint url")
	adcsCmd.Flags().String("oid-template", "", "OID string usually selected in the ADCS template dropdown")
	adcsCmd.Flags().String("auth", "", "Authorization method for AD Certificate Services endpoint: ntlm or kerberos")
	adcsCmd.Flags().String("krb5conf", "", "Path to a kerberos config file containing realms (with KDCs) and domain_realm sections in lieu of specifying kdcs")
	adcsCmd.Flags().StringP("user", "u", "", "Username to use for authentication")
	adcsCmd.Flags().String("realm", "", "Realm to use for kerberos authentication")
	adcsCmd.Flags().StringP("keytab", "k", "", "Keytab file to use for kerberos authentication")
	adcsCmd.Flags().StringSlice("kdcs", []string{}, "A comma separated list of KDC servers to use for kerberos authentication")

	viper.BindPFlag("adcs-url", adcsCmd.Flags().Lookup("adcs-url"))
	viper.BindPFlag("oid-template", adcsCmd.Flags().Lookup("oid-template"))
	viper.BindPFlag("adcs-auth.method", adcsCmd.Flags().Lookup("auth"))
	viper.BindPFlag("adcs-auth.krb5conf", adcsCmd.Flags().Lookup("krb5conf"))
	viper.BindPFlag("adcs-auth.user", adcsCmd.Flags().Lookup("user"))
	viper.BindPFlag("adcs-auth.realm", adcsCmd.Flags().Lookup("realm"))
	viper.BindPFlag("adcs-auth.keytab", adcsCmd.Flags().Lookup("keytab"))
	viper.BindPFlag("adcs-auth.kdcs", adcsCmd.Flags().Lookup("kdcs"))

	// setting the default in the String() func above does not work
	viper.SetDefault("adcs-auth.method", "ntlm")

	// add adcs sub-command
	certCmd.AddCommand(adcsCmd)
}
