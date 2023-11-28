// Copyright © 2019 Lawrence Livermore National Security, LLC
// SPDX-License-Identifier: MIT
// See top-level LICENSE file for details.

package http

import (
	"bufio"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"path"
	"regexp"
	"strings"
	"time"

	ntlmssp "github.com/Azure/go-ntlmssp"
)

type CertConfig struct {
	AdcsUrl     string
	OidTemplate string
}

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
	client := &http.Client{
		Transport: ntlmssp.Negotiator{
			RoundTripper: &http.Transport{},
		},
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
	req.SetBasicAuth(user, pass)

	// get response
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
	certReq.SetBasicAuth(user, pass)
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
