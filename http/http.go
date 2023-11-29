// Copyright © 2019 Lawrence Livermore National Security, LLC
// SPDX-License-Identifier: MIT
// See top-level LICENSE file for details.

package http

import (
	"bufio"
	"bytes"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"path"
	"regexp"
	"strings"
	"text/template"
	"time"

	gokrb5 "github.com/jcmturner/gokrb5/v8/client"
	gokrb5conf "github.com/jcmturner/gokrb5/v8/config"
	ntlmssp "github.com/Azure/go-ntlmssp"
	spnego "github.com/jcmturner/gokrb5/v8/spnego"
)

type CertConfig struct {
	AdcsUrl          string
	OidTemplate      string
	AdcsAuthMethod   string
	AdcsAuthKrb5conf string
	AdcsAuthRealm    string
	AdcsAuthKdcs     []string
}

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

func PostAdcsRequest(user, pass, csr string, config *CertConfig) (cert []byte, err error) {
	// build POST data
	form := url.Values{}
	form.Add("CertRequest", csr)
	form.Add("TargetStoreFlags", "0")
	form.Add("SaveCert", "yes")
	form.Add("Mode", "newreq")
	form.Add("FriendlyType", fmt.Sprintf("Saved-Request Certificate (%s)", time.Now().Format("1/2/2006, 3:04:05 PM")))
	form.Add("ThumbPrint", "")
	form.Add("CertAttrib", fmt.Sprintf("CertificateTemplate:%s\r\nUserAgent:Go-http-client/1.1\r\n", config.OidTemplate))
	body := strings.NewReader(form.Encode())

	// indicate NTLM auth
	//client := &http.Client {
	//	Transport: ntlmssp.Negotiator {
	//		RoundTripper: &http.Transport {},
	//	},
	//}

	// Kerberos
	funcList := template.FuncMap{"ToUpper": strings.ToUpper, "ToLower": strings.ToLower}
	t := template.Must(template.New("").Funcs(funcList).Parse(Krb5Config))
	buffer := &bytes.Buffer{}
	if err := t.Execute(buffer, *config); err != nil {
		return cert, fmt.Errorf("error creating kerberos config: %s", err)
	}
	var cfg *gokrb5conf.Config
	if config.AdcsAuthKrb5conf != "" {
		cfg, err = gokrb5conf.Load(config.AdcsAuthKrb5conf)
		if err != nil {
			return cert, fmt.Errorf("error loading kerberos config: %s", err)
		}
	} else {
		cfg = gokrb5conf.New()
	}
	krb5Client := gokrb5.NewWithPassword(user, config.AdcsAuthRealm, pass, cfg, gokrb5.DisablePAFXFAST(true))
	err = krb5Client.Login()
	defer krb5Client.Destroy()
	if err != nil {
		return cert, fmt.Errorf("error obtaining kerberos ticket: %s", err)
	}

	// build url
	certfnshUrl, err := url.Parse(config.AdcsUrl)
	if err != nil {
		return cert, fmt.Errorf("invalid adcs-url: %s", err)
	}
	certfnshUrl.Path = path.Join(certfnshUrl.Path, "certfnsh.asp")

	// build request
	req, err := http.NewRequest("POST", certfnshUrl.String(), body)
	if err != nil {
		return
	}
	req.Header.Add("Content-Type", "application/x-www-form-urlencoded")
	//TODO: if !kerberos
	//req.SetBasicAuth(user, pass)

	// get response
	//TODO: if kerberos
	client := spnego.NewClient(krb5Client, nil, "")
	resp, err := client.Do(req)
	if err != nil {
		return
	}
	defer resp.Body.Close()

	// get issued certificate request ID
	requestId := ""
	if resp.StatusCode != http.StatusOK {
		content, _ := io.ReadAll(resp.Body)
		fmt.Printf("response:\n%s\n", content)
		return cert, fmt.Errorf("certificate issue request returned status code: %d", resp.StatusCode)
	} else if resp.StatusCode == http.StatusOK {
		scanner := bufio.NewScanner(resp.Body)
		for scanner.Scan() {
			if strings.Contains(scanner.Text(), "locDownloadCert1") {
				expr := regexp.MustCompile(`ReqID=([^&]+)&`)
				match := expr.FindStringSubmatch(scanner.Text())
				if len(match) == 2 { // found a Request ID, extract it
					requestId = match[1]
					fmt.Printf("server issued certificate with request ID %s\n", requestId)
					break
				}
			}
		}
	}
	if requestId == "" {
		return cert, fmt.Errorf("did not receive an issued certificate from the server")
	}

	// build issued cert url
	certnewUrl, err := url.Parse(config.AdcsUrl)
	if err != nil {
		return cert, fmt.Errorf("invalid adcs-url: %s", err)
	}
	certnewUrl.Path = path.Join(certnewUrl.Path, "certnew.cer")
	query := certnewUrl.Query()
	query.Set("ReqID", requestId)
	query.Set("Enc", "b64")
	certnewUrl.RawQuery = query.Encode()

	// download issued cert
	certReq, err := http.NewRequest("GET", certnewUrl.String(), nil)
	if err != nil {
		return cert, fmt.Errorf("could not initiate cert download request: %v", err)
	}
	//TODO: if !kerberos
	//certReq.SetBasicAuth(user, pass)
	certResp, err := client.Do(certReq)
	if err != nil {
		return cert, fmt.Errorf("could not download issued cert: %v", err)
	}
	defer certResp.Body.Close()
	if certResp.StatusCode == http.StatusOK {
		cert, err = io.ReadAll(certResp.Body)
	} else {
		content, _ := io.ReadAll(certResp.Body)
		fmt.Printf("response:\n%s\n", content)
		return cert, fmt.Errorf("download request returned status code: %d", certResp.StatusCode)
	}

	return
}
