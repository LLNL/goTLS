// Copyright © 2019 Lawrence Livermore National Security, LLC
// SPDX-License-Identifier: MIT
// See top-level LICENSE file for details.

package cmd

import (
	"log/slog"
	"os"
	"runtime/debug"

	homedir "github.com/mitchellh/go-homedir"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

var logLevel *slog.LevelVar
var confFile string
var verbose bool
var version bool

// RootCmd represents the base command when called without any subcommands
var RootCmd = &cobra.Command{
	Use:   "gotls",
	Short: "gotls is a TLS certificate issuance and management tool",
	Long: `gotls can generate keys, CSRs, and obtain a certificate
from an Active Directory Certificate Services endpoint.`,
	SilenceErrors: true,
	SilenceUsage:  true,
	Run: func(cmd *cobra.Command, args []string) {
		if version {
			// print binary version (uses semver pre-release syntax vs git describe post-release)
			// if git describe outputs v0.1.0-19-ge626b7c (e626b7c is 19 commits after the v0.1.0 tag),
			// semver would call this v0.1.1-pre release. Version will read v0.1.1-0.20250603183735-e626b7c4ea5a
			info, ok := debug.ReadBuildInfo()
			if !ok {
				slog.Error("could not read build info from binary")
				os.Exit(1)
			}
			slog.Info("GoTLS", "version", info.Main.Version)

			if verbose {
				// collect build info
				settings := []any{
					"module", info.Main.Path,
					"go", info.GoVersion,
				}
				for _, setting := range info.Settings {
					switch setting.Key {
					case "GOOS":
						settings = append(settings, "os")
						settings = append(settings, setting.Value)
					case "GOARCH":
						settings = append(settings, "arch")
						settings = append(settings, setting.Value)
					case "vcs.time":
						settings = append(settings, "time")
						settings = append(settings, setting.Value)
					case "vcs.revision":
						settings = append(settings, "commit")
						settings = append(settings, setting.Value)
					case "vcs.modified":
						settings = append(settings, "modified")
						settings = append(settings, setting.Value)
					}
				}

				// print build info
				slog.Debug("build info", settings...)
			}
		} else {
			cmd.Help()
		}
	},
}

// Execute adds all child commands to the root command and sets flags appropriately.
func Execute(level *slog.LevelVar) (err error) {
	logLevel = level

	if err := RootCmd.Execute(); err != nil {
		return err
	}

	return
}

// this init() must be called before other command's init functions in order for the GenerateRevalidateViperKeyFn
// workaround to take effect
func init() {
	cobra.OnInitialize(GenerateRevalidateViperKeyFn())

	RootCmd.PersistentFlags().StringVar(&confFile, "config", "",
		"config file (default is ./.gotls.yaml or $HOME/.gotls.yaml)")
	RootCmd.PersistentFlags().BoolVarP(&verbose, "verbose", "v", false, "enables verbose output")
	RootCmd.PersistentFlags().BoolVarP(&version, "version", "V", false, "prints version info; +build info if combined with verbose")

	RootCmd.CompletionOptions.HiddenDefaultCmd = true

	initKey()
	initCsr()
	initCert()
}

// GenerateRevalidateViperKeyFn is used to read flags into nested config structure (workaround spf13/viper issue #368)
// from https://github.com/spf13/viper/pull/487#issuecomment-685422963
func GenerateRevalidateViperKeyFn() func() {
	return func() { initConfig("global") }
}

// initConfig reads in config file and ENV variables if set.
func initConfig(keyOrParent string) {
	if confFile != "" {
		viper.SetConfigFile(confFile)
	} else {
		viper.AddConfigPath(".") // override config from the working directory

		home, err := homedir.Dir()
		if err != nil {
			slog.Error("could not obtain home directory", slog.Any("error", err))
			os.Exit(1)
		}
		viper.AddConfigPath(home)
		viper.SetConfigName(".gotls") // do not set the extension; viper will try all known types
	}

	viper.AutomaticEnv() // read in environment variables that match

	if err := viper.ReadInConfig(); err != nil {
		if _, ok := err.(viper.ConfigFileNotFoundError); !ok { // Config file was found but another error was produced
			slog.Error("could not read config", slog.Any("error", err))
			os.Exit(1)
		}
	}

	// update log level to debug (after viper and cobra are initialized)
	if verbose {
		logLevel.Set(slog.LevelDebug)
	}
	slog.Debug("read config file", "filename", viper.ConfigFileUsed())

	viper.Set(keyOrParent, viper.AllSettings()[keyOrParent])
}
