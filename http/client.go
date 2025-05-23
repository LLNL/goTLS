// Copyright © 2023 Lawrence Livermore National Security, LLC
// SPDX-License-Identifier: MIT
// See top-level LICENSE file for details.

package http

import (
	"fmt"
	"net/http"

	ntlmssp "github.com/Azure/go-ntlmssp"
	gokrb5 "github.com/jcmturner/gokrb5/v8/client"
	gokrb5conf "github.com/jcmturner/gokrb5/v8/config"
	"github.com/jcmturner/gokrb5/v8/keytab"
	spnego "github.com/jcmturner/gokrb5/v8/spnego"
)

type Client struct {
	authMethod   AuthMethod
	httpClient   *http.Client
	spnegoClient *spnego.Client
	krb5Client   *gokrb5.Client
}

func NewClient(authMethod AuthMethod, user, pass, keytabFilename, realm, krb5Config string) (*Client, error) {
	if authMethod == Ntlm {
		httpClient := &http.Client{
			Transport: ntlmssp.Negotiator{
				RoundTripper: &http.Transport{},
			},
		}

		return &Client{httpClient: httpClient, authMethod: authMethod}, nil
	} else if authMethod == Kerberos {
		// load krb5 config
		if krb5Config != "" {
			cfg, err := gokrb5conf.NewFromString(krb5Config)
			if err != nil {
				return nil, fmt.Errorf("could not load kerberos config: %w", err)
			}

			var krb5Client *gokrb5.Client
			if keytabFilename != "" {
				// authenticate with keytab for credential
				kt, err := keytab.Load(keytabFilename)
				if err != nil {
					return nil, fmt.Errorf("could not load kerberos keytab: %w", err)
				}
				krb5Client = gokrb5.NewWithKeytab(user, realm, kt, cfg, gokrb5.DisablePAFXFAST(true))
			} else {
				// authenticate with password for credential
				krb5Client = gokrb5.NewWithPassword(user, realm, pass, cfg, gokrb5.DisablePAFXFAST(true))
			}
			err = krb5Client.Login()
			if err != nil {
				return nil, fmt.Errorf("could not obtain kerberos ticket: %w", err)
			}

			spnegoClient := spnego.NewClient(krb5Client, nil, "")

			return &Client{spnegoClient: spnegoClient, krb5Client: krb5Client, authMethod: authMethod}, nil
		} else {
			return nil, fmt.Errorf("could not load kerberos config: passed configuration is empty")
		}
	} else {
		return nil, fmt.Errorf("invalid auth method specified for client: %d", authMethod)
	}
}

func (c *Client) Do(req *http.Request) (*http.Response, error) {
	if c.authMethod == Ntlm {
		return c.httpClient.Do(req)
	} else if c.authMethod == Kerberos {
		return c.spnegoClient.Do(req)
	} else {
		return nil, fmt.Errorf("invalid auth method specified for client: %d", c.authMethod)
	}
}

func (c *Client) Destroy() {
	if c.krb5Client != nil {
		c.krb5Client.Destroy()
	}
}
