// Copyright © 2023 Lawrence Livermore National Security, LLC
// SPDX-License-Identifier: MIT
// See top-level LICENSE file for details.

package http

import (
	"fmt"
	"net"
)

const (
	Ntlm AuthMethod = 1 << iota
	Kerberos
)

const Krb5Config = `[libdefaults]
  dns_lookup_realm = false
  dns_lookup_kdc = false
  ticket_lifetime = 24h
  forwardable = yes
  default_tkt_enctypes = aes256-cts-hmac-sha1-96
  default_tgs_enctypes = aes256-cts-hmac-sha1-96
  noaddresses = false
  default_realm = {{ToUpper .AdcsAuthRealm}}

[realms]
  {{ToUpper .AdcsAuthRealm}} = {
{{- range .AdcsAuthKdcs}}
    kdc = {{ToLower .}}
{{- end}}
 }

[domain_realm]
  .{{ToLower .AdcsAuthRealm}} = {{ToUpper .AdcsAuthRealm}}
  {{ToLower .AdcsAuthRealm}} = {{ToUpper .AdcsAuthRealm}}
`

type AuthMethod byte

type CsrConfig struct {
	CN    string
	C     string
	ST    string
	L     string
	O     string
	OU    string
	Email string
	DNS   []string
	IP    []net.IP
}

type CertConfig struct {
	AdcsUrl          string
	OidTemplate      string
	AdcsAuthMethods  AuthMethod
	AdcsAuthKrb5conf string
	AdcsAuthUser     string
	AdcsAuthRealm    string
	AdcsAuthKeytab   string
	AdcsAuthKdcs     []string
}

var AuthMethodMap = map[string]AuthMethod{
	"ntlm":     Ntlm,
	"kerberos": Kerberos,
}

func (config *CertConfig) ClearAuthMethods() {
	config.AdcsAuthMethods = 0
}

func (config *CertConfig) HasAuthMethod(method AuthMethod) bool {
	return config.AdcsAuthMethods&method != 0
}

func (config *CertConfig) SetAuthMethod(method AuthMethod) {
	config.ClearAuthMethods()
	config.AdcsAuthMethods |= method
}

func (config *CertConfig) SetAuthMethodString(methodString string) {
	method := AuthMethodMap[methodString]

	config.SetAuthMethod(method)
}

func (authMethod AuthMethod) String() string {
	if authMethod > Kerberos {
		return fmt.Sprintf("unknown auth method: %d", authMethod)
	}

	switch authMethod {
	case Ntlm:
		return "ntlm"
	case Kerberos:
		return "kerberos"
	}

	return ""
}
