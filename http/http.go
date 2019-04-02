// Copyright © 2019 Lawrence Livermore National Security
// See LICENSE file

package http

import (
	"fmt"
	"io/ioutil"
	"net/http"
)

func PostAdcsRequest(adcsUrl, user, pass, csr string) (err error) {
	// build post request
	client := &http.Client {}
	req, err := http.NewRequest("POST", adcsUrl, nil)
	if err != nil {
		return err
	}
	req.SetBasicAuth(user, pass)

	//TODO: build POST data

	// get response
	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	body, err := ioutil.ReadAll(resp.Body)

	//TODO: actually handle the response
	fmt.Printf("%s", string(body))

	return err
}