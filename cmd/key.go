// Copyright © 2019 Lawrence Livermore National Security, LLC
// SPDX-License-Identifier: MIT
// See top-level LICENSE file for details.

package cmd

import (
	"crypto/x509"
	"fmt"
	"log/slog"
	"os"
	"strconv"
	"strings"

	"github.com/spf13/cobra"
	"github.com/spf13/viper"

	"github.com/llnl/gotls/crypto"
)

var algorithm, container string
var ecSize, rsaSize int

// keyCmd represents the key command
var keyCmd = &cobra.Command{
	Use:   "key [Flags] hostname.fq.dn",
	Short: "Generate RSA private key",
	Long: `Generate RSA private key and write to a file.
The filename can be provided either to the --output parameter or will be
constructed from the first argument to this command, appended with .key,
and written to the current directory (hostname.fq.dn.key).`,
	Args:                  cobra.MaximumNArgs(1),
	DisableFlagsInUseLine: true,
	Run: func(cmd *cobra.Command, args []string) {
		// get output filename
		if len(args) == 1 {
			if outputFilename != "" {
				slog.Error("Output filename must be specified in either --output parameter or as the first argument to the key command; not both.")
				os.Exit(1)
			} else {
				outputFilename = fmt.Sprintf("%s.key", args[0])
			}
		} else if len(args) == 0 {
			if outputFilename == "" {
				slog.Error("Output filename must be specified in either --output parameter or as the first argument to the key command.")
				os.Exit(1)
			}
		}

		// default key parameters
		keyRequest := &crypto.KeyRequest{
			Filename:  outputFilename,
			Type:      x509.RSA,
			Container: crypto.PKCS1,
			EcSize:    crypto.P256,
			RsaSize:   rsaSize,
		}

		// load flags from command line or config
		if viper.IsSet("algorithm") {
			algorithm = viper.GetString("algorithm")
		}
		if viper.IsSet("container") {
			container = viper.GetString("container")
		}
		if viper.IsSet("ec-size") {
			ecSize = viper.GetInt("ec-size")
		}
		if viper.IsSet("rsa-size") {
			rsaSize = viper.GetInt("rsa-size")
		}

		// validate flags
		switch strings.ToLower(algorithm) {
		case strings.ToLower(x509.RSA.String()):
			keyRequest.Type = x509.RSA
		case strings.ToLower(x509.ECDSA.String()):
			keyRequest.Type = x509.ECDSA
		case strings.ToLower(x509.Ed25519.String()):
			keyRequest.Type = x509.Ed25519
		default:
			slog.Error("invalid algorithm specified", "algorithm", algorithm)
			os.Exit(1)
		}
		switch strings.ToLower(container) {
		case "pkcs1":
			fallthrough
		case "pkcs#1":
			fallthrough
		case "pkcs 1":
			keyRequest.Container = crypto.PKCS1
		case "pkcs8":
			fallthrough
		case "pkcs#8":
			fallthrough
		case "pkcs 8":
			keyRequest.Container = crypto.PKCS8
		case "sec1":
			fallthrough
		case "sec#1":
			fallthrough
		case "sec 1":
			keyRequest.Container = crypto.SEC1
			//TODO: SEC1 can only contain ECDSA
		default:
			slog.Error("invalid container specified", "container", container)
			os.Exit(1)
		}
		switch ecSize {
		case 224:
			keyRequest.EcSize = crypto.P224
		case 256:
			keyRequest.EcSize = crypto.P256
		case 384:
			keyRequest.EcSize = crypto.P384
		case 521:
			keyRequest.EcSize = crypto.P521
		default:
			slog.Error(fmt.Sprintf("invalid ec-size specified. use %s, %s, %s, or %s implementations.",
				crypto.P224.String(), crypto.P256.String(), crypto.P384.String(), crypto.P521.String()),
				"ec-size", ecSize)
		}

		// create a new key
		CreateKey(keyRequest)
	},
}

func CreateKey(keyRequest *crypto.KeyRequest) (key any) {
	// generate key
	key, err := crypto.GenerateKey(keyRequest)
	if err != nil {
		slog.Error("could not generate private key", "filename", keyRequest.Filename, slog.Any("error", err))
		os.Exit(1)
	}

	// write key to file
	if err = crypto.WriteKey(key, keyRequest); err != nil {
		slog.Error("could not write private key", slog.Any("error", err))
		os.Exit(1)
	}

	// format and write success message
	args := []any{
		"filename", keyRequest.Filename,
		"type", keyRequest.Type.String(),
		"container", keyRequest.Container.String(),
	}
	switch keyRequest.Type {
	case x509.RSA:
		args = append(args, "rsa-size", strconv.Itoa(rsaSize))
	case x509.ECDSA:
		args = append(args, "ec-size", keyRequest.EcSize.String())
	}
	slog.Info("wrote private key", args...)

	return key
}

func initKey() {
	keyCmd.Flags().StringVarP(&algorithm, "algorithm", "a", "rsa", "Encryption algorthm to use: rsa, ecdsa, or ed25519")
	keyCmd.Flags().StringVarP(&container, "container", "c", "pkcs1", "Container format to store key in ASN.1, DER, PEM form: pkcs1, pkcs8, sec1")
	keyCmd.Flags().IntVarP(&ecSize, "ec-size", "", 256, "Elliptic Curve bit size/NIST implementation to use: 224, 256, 384, 521")
	keyCmd.Flags().IntVarP(&rsaSize, "rsa-size", "", 2048, "RSA bit size to use")
	keyCmd.Flags().StringVarP(&outputFilename, "output", "o", "", "Filename for writing private key (default is hostname.fq.dn.key)")

	// bind flags to conf file values
	viper.BindPFlag("algorithm", keyCmd.Flags().Lookup("algorithm"))
	viper.BindPFlag("container", keyCmd.Flags().Lookup("container"))
	viper.BindPFlag("ec-size", keyCmd.Flags().Lookup("ec-size"))
	viper.BindPFlag("rsa-size", keyCmd.Flags().Lookup("rsa-size"))

	RootCmd.AddCommand(keyCmd)
}
