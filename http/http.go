// Copyright © 2019 Lawrence Livermore National Security, LLC
// SPDX-License-Identifier: MIT
// See top-level LICENSE file for details.

package http

import (
	"bufio"
	"bytes"
	"fmt"
	"io"
	"log/slog"
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
	Cert     []byte
	Filename string
}

func PostAdcsRequest(user, pass string, csrs []CsrRequest, config *CertConfig) (certs []CertResponse, errors []error) {
	var client *Client
	var certResp *http.Response

	// build cert request url
	certfnshUrl, err := url.Parse(config.AdcsUrl)
	if err != nil {
		return certs, []error{fmt.Errorf("invalid adcs-url: %w", err)}
	}
	certfnshUrl.Path = path.Join(certfnshUrl.Path, "certfnsh.asp")

	// build issued cert url
	certnewUrl, err := url.Parse(config.AdcsUrl)
	if err != nil {
		return certs, []error{fmt.Errorf("invalid adcs-url: %w", err)}
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
				return certs, []error{fmt.Errorf("could not load kerberos config: %w", err)}
			}
			krb5Config = string(configBytes)
		} else {
			// build krb5 config
			funcList := template.FuncMap{"ToUpper": strings.ToUpper, "ToLower": strings.ToLower}
			t := template.Must(template.New("").Funcs(funcList).Parse(Krb5Config))
			buffer := &bytes.Buffer{}
			if err = t.Execute(buffer, *config); err != nil {
				return certs, []error{fmt.Errorf("could not create kerberos config: %w", err)}
			}
			krb5Config = buffer.String()
		}

		// ensure uppercase realm name
		realm := strings.ToUpper(config.AdcsAuthRealm)

		client, err = NewClient(Kerberos, user, pass, config.AdcsAuthKeytab, realm, krb5Config)
		if err != nil {
			return certs, []error{fmt.Errorf("could not create auth client: %w", err)}
		}
	}
	slog.Debug("using auth method", "adcs-auth.method", config.AdcsAuthMethods.String())

	if err != nil {
		return certs, []error{err}
	}
	defer client.Destroy()

	for _, csr := range csrs {
		// create child logger with CSR context
		logger := slog.Default().With("filename", csr.Filename)

		logger.Debug("processing csr", "url", certfnshUrl.String())

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
			return certs, []error{err}
		}
		req.Header.Add("Content-Type", "application/x-www-form-urlencoded")
		if config.HasAuthMethod(Ntlm) {
			req.SetBasicAuth(user, pass)
		}

		// get response
		resp, err := client.Do(req)
		if err != nil {
			return certs, []error{err}
		}
		defer resp.Body.Close()

		// get issued certificate request ID
		requestId := ""
		if resp.StatusCode != http.StatusOK {
			content, _ := io.ReadAll(resp.Body)
			logger.Error("certificate issue request failed", "StatusCode", resp.StatusCode, "response", content)
			errors = append(errors, fmt.Errorf("certificate issue request failed"))
			continue
		} else if resp.StatusCode == http.StatusOK {
			scanner := bufio.NewScanner(resp.Body)
			for scanner.Scan() {
				if strings.Contains(scanner.Text(), "locDownloadCert1") {
					expr := regexp.MustCompile(`ReqID=([^&]+)&`)
					match := expr.FindStringSubmatch(scanner.Text())
					if len(match) == 2 { // found a Request ID, extract it
						requestId = match[1]
						logger.Info("server issued certificate", "ReqID", requestId)
						break
					}
				}
			}
		}
		if requestId == "" {
			logger.Error("did not receive an issued certificate from the server")
			errors = append(errors, fmt.Errorf("could not get certificate"))
			continue
		}

		logger.Debug("getting certificate", "url", certnewUrl.String())

		query := certnewUrl.Query()
		query.Set("ReqID", requestId)
		query.Set("Enc", "b64")
		certnewUrl.RawQuery = query.Encode()

		// download issued cert
		certReq, err := http.NewRequest("GET", certnewUrl.String(), nil)
		if err != nil {
			logger.Error("could not initiate certificate download request", slog.Any("error", err))
			errors = append(errors, fmt.Errorf("could not get certificate"))
			continue
		}

		// get response
		certResp, err = client.Do(certReq)
		if err != nil {
			logger.Error("could not download issued certificate", slog.Any("error", err))
			errors = append(errors, fmt.Errorf("could not get certificate"))
			continue
		}
		if certResp.StatusCode != http.StatusOK {
			content, _ := io.ReadAll(certResp.Body)
			logger.Error("certificate download request failed", "StatusCode", certResp.StatusCode, "response", content)
			errors = append(errors, fmt.Errorf("certificate download request failed"))
			certResp.Body.Close()
			continue
		} else {
			cert, err := io.ReadAll(certResp.Body)
			if err != nil {
				logger.Error("could not read certificate download", slog.Any("error", err))
				errors = append(errors, fmt.Errorf("could not get certificate"))
				certResp.Body.Close()
				continue
			} else {
				certs = append(certs, CertResponse{
					Cert:     cert,
					Filename: fmt.Sprintf("%s.crt", strings.TrimSuffix(csr.Filename, ".csr")),
				})
				certResp.Body.Close()
			}
		}
	}

	return certs, errors
}
