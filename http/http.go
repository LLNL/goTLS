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
	"os"
	"path"
	"regexp"
	"strings"
	"text/template"
	"time"
)

type CsrRequest struct {
	Content  []byte
	Filename string
}

type CertResponse struct {
	Cert        []byte
	CsrFilename string
	Error       error
}

func PostAdcsRequest(user, pass string, csrs []CsrRequest, config *CertConfig, verbose bool) (certs []CertResponse, err error) {
	var client *Client
	var certResp *http.Response

	// build cert request url
	certfnshUrl, err := url.Parse(config.AdcsUrl)
	if err != nil {
		return certs, fmt.Errorf("invalid adcs-url: %s", err)
	}
	certfnshUrl.Path = path.Join(certfnshUrl.Path, "certfnsh.asp")

	// build issued cert url
	certnewUrl, err := url.Parse(config.AdcsUrl)
	if err != nil {
		return certs, fmt.Errorf("invalid adcs-url: %s", err)
	}
	certnewUrl.Path = path.Join(certnewUrl.Path, "certnew.cer")

	// configure client for auth method
	if config.HasAuthMethod(Ntlm) {
		client, err = NewClient(Ntlm, "", "", "", "", "")
	} else if config.HasAuthMethod(Kerberos) {
		var krb5Config string
		if config.AdcsAuthKrb5conf != "" {
			// load krb5 config
			var configBytes []byte
			if configBytes, err = os.ReadFile(config.AdcsAuthKrb5conf); err != nil {
				return certs, fmt.Errorf("error loading kerberos config: %s", err)
			}
			krb5Config = string(configBytes)
		} else {
			// build krb5 config
			funcList := template.FuncMap{"ToUpper": strings.ToUpper, "ToLower": strings.ToLower}
			t := template.Must(template.New("").Funcs(funcList).Parse(Krb5Config))
			buffer := &bytes.Buffer{}
			if err = t.Execute(buffer, *config); err != nil {
				return certs, fmt.Errorf("error creating kerberos config: %s", err)
			}
			krb5Config = buffer.String()
		}

		// ensure uppercase realm name
		realm := strings.ToUpper(config.AdcsAuthRealm)

		client, err = NewClient(Kerberos, user, pass, config.AdcsAuthKeytab, realm, krb5Config)
	}
	if verbose {
		fmt.Printf("client auth method: %s\n", config.AdcsAuthMethods.String())
	}

	if err != nil {
		return certs, err
	}
	defer client.Destroy()

	for _, csr := range csrs {
		if verbose {
			fmt.Printf("processing %s\n", csr.Filename)
			fmt.Printf("post request: %s\n", certfnshUrl.String())
		}

		// build POST data
		form := url.Values{}
		form.Add("CertRequest", string(csr.Content))
		form.Add("TargetStoreFlags", "0")
		form.Add("SaveCert", "yes")
		form.Add("Mode", "newreq")
		form.Add("FriendlyType", fmt.Sprintf("Saved-Request Certificate (%s)", time.Now().Format("1/2/2006, 3:04:05 PM")))
		form.Add("ThumbPrint", "")
		form.Add("CertAttrib", fmt.Sprintf("CertificateTemplate:%s\r\nUserAgent:GoTLS/0.2\r\n", config.OidTemplate))
		body := strings.NewReader(form.Encode())

		// build request
		req, err := http.NewRequest("POST", certfnshUrl.String(), body)
		if err != nil {
			return []CertResponse{}, err
		}
		req.Header.Add("Content-Type", "application/x-www-form-urlencoded")
		if config.HasAuthMethod(Ntlm) {
			req.SetBasicAuth(user, pass)
		}

		// get response
		resp, err := client.Do(req)
		if err != nil {
			return []CertResponse{}, err
		}
		defer resp.Body.Close()

		// get issued certificate request ID
		requestId := ""
		if resp.StatusCode != http.StatusOK {
			content, _ := io.ReadAll(resp.Body)
			certs = append(certs, CertResponse{
				Cert:        []byte{},
				CsrFilename: csr.Filename,
				Error:       fmt.Errorf("certificate issue request returned status code: %d, response: %s", resp.StatusCode, content),
			})
			err = fmt.Errorf("error getting cert")
			continue
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
			certs = append(certs, CertResponse{
				Cert:        []byte{},
				CsrFilename: csr.Filename,
				Error:       fmt.Errorf("did not receive an issued certificate from the server"),
			})
			err = fmt.Errorf("error getting cert")
			continue
		}

		if verbose {
			fmt.Printf("get request: %s\n", certnewUrl.String())
		}

		query := certnewUrl.Query()
		query.Set("ReqID", requestId)
		query.Set("Enc", "b64")
		certnewUrl.RawQuery = query.Encode()

		// download issued cert
		certReq, err := http.NewRequest("GET", certnewUrl.String(), nil)
		if err != nil {
			certs = append(certs, CertResponse{
				Cert:        []byte{},
				CsrFilename: csr.Filename,
				Error:       fmt.Errorf("could not initiate cert download request: %v", err),
			})
			err = fmt.Errorf("error getting cert")
			continue
		}

		// get response
		certResp, err = client.Do(certReq)
		if err != nil {
			certs = append(certs, CertResponse{
				Cert:        []byte{},
				CsrFilename: csr.Filename,
				Error:       fmt.Errorf("could not download issued cert: %v", err),
			})
			err = fmt.Errorf("error getting cert")
			continue
		}
		if certResp.StatusCode != http.StatusOK {
			content, _ := io.ReadAll(certResp.Body)
			certs = append(certs, CertResponse{
				Cert:        []byte{},
				CsrFilename: csr.Filename,
				Error:       fmt.Errorf("download request returned status code: %d, response: %s", certResp.StatusCode, content),
			})
			err = fmt.Errorf("error getting cert")
			certResp.Body.Close()
			continue
		} else {
			cert, err := io.ReadAll(certResp.Body)
			if err != nil {
				certs = append(certs, CertResponse{
					Cert:        []byte{},
					CsrFilename: csr.Filename,
					Error:       fmt.Errorf("could not read cert response: %s", err),
				})
				err = fmt.Errorf("error getting cert")
				certResp.Body.Close()
				continue
			} else {
				certs = append(certs, CertResponse{
					Cert:        cert,
					CsrFilename: csr.Filename,
				})
				certResp.Body.Close()
			}
		}
	}

	return
}
