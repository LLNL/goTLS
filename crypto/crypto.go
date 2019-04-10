// Copyright © 2019 Lawrence Livermore National Security
// See LICENSE file

package crypto

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/pem"
	"fmt"
	"io/ioutil"
	"os"
)

type BasicConstraints struct {
	IsCA bool `asn1:"optional"`
}

func GetKey(fileName string, rsaSize int) (key *rsa.PrivateKey, err error) {
	// check for existing key
	if _, err = os.Stat(fileName); err == nil { // key exists
		fmt.Printf("Loading existing private key\n")
		keyBytes, err := ioutil.ReadFile(fileName)
		if err != nil {
			return key, err
		}

		block, _ := pem.Decode(keyBytes)
		if block == nil {
			return key, fmt.Errorf("could not decode private key")
		}

		key, err := x509.ParsePKCS1PrivateKey(block.Bytes)
		if err != nil {
			return key, fmt.Errorf("invalid pkcs1 key format: %s", err)
		}
	} else {
		fmt.Printf("Generating new private key\n")
		// generate private key
		key, err = rsa.GenerateKey(rand.Reader, rsaSize)
		if err != nil {
			return
		}

		// get PEM block for private key
		block := &pem.Block{
			Type:  "RSA PRIVATE KEY",
			Bytes: x509.MarshalPKCS1PrivateKey(key),
		}

		// write out PEM block to file
		keyFile, err := os.OpenFile(fileName, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0600)
		if err != nil {
			return key, fmt.Errorf("while opening %s for writing: %s", fileName, err)
		}
		if err := pem.Encode(keyFile, block); err != nil {
			keyFile.Close()
			return key, fmt.Errorf("failed to write data to %s: %s", fileName, err)
		}
		if err := keyFile.Close(); err != nil {
			return key, fmt.Errorf("while closing %s: %s", fileName, err)
		}

		fmt.Printf("Wrote private key to %s\n", fileName)
	}

	return
}

func GenerateCsr(fileName string, key *rsa.PrivateKey, cn string, dns []string, c, st, l, o, ou, email string) (block *pem.Block, err error) {
	// populate subject fields (designating CN as required)
	subject := pkix.Name {
		CommonName: cn,
	}
	if c != "" {
		subject.Country = []string{ c }
	}
	if st != "" {
		subject.Province = []string{ st }
	}
	if l != "" {
		subject.Locality = []string{ l }
	}
	if o != "" {
		subject.Organization = []string{ o }
	}
	if ou != "" {
		subject.OrganizationalUnit = []string{ ou }
	}
	if email != "" {
		// using subject.EmailAddresses would set the email in the SAN field (for email certificates)
		subject.ExtraNames = []pkix.AttributeTypeAndValue {
			pkix.AttributeTypeAndValue {
				Type: asn1.ObjectIdentifier{ 1, 2, 840, 113549, 1, 9, 1 },
				Value: asn1.RawValue {
					Tag: asn1.TagIA5String,
					Bytes: []byte(email),
				},
			},
		}
	}
	//TODO: StreetAddress
	//TODO: PostalCode
	//TODO: IPAddresses

	basicConstraints, err := asn1.Marshal(BasicConstraints{false})
	if err != nil {
		return block, fmt.Errorf("could not encode CA constraint into asn1 format: %s", err)
	}

	// populate CSR template
	template := &x509.CertificateRequest {
		SignatureAlgorithm: x509.SHA256WithRSA,
		Subject: subject,
		ExtraExtensions: []pkix.Extension {
			// key usage
			pkix.Extension {
				Id: asn1.ObjectIdentifier{ 2, 5, 29, 15 },
				Critical: false,
				Value: []byte{ 0x03, 0x02, 0x03, 0xe0 }, // 0x03: 3 bits; 0xe0: digitalSignature(0),nonRepudiation(1),keyEncipherment(2)
			},
			// Basic constraint: CA=false
			pkix.Extension {
				Id: asn1.ObjectIdentifier{ 2, 5, 29, 19 },
				Critical: false,
				Value: basicConstraints,
			},
		},
	}
	if len(dns) > 0 {
		template.DNSNames = dns
	}

	// create CSR
	der, err := x509.CreateCertificateRequest(rand.Reader, template, key)
	if err != nil {
		return
	}

	// get PEM block for CSR
	block = &pem.Block {
		Type: "CERTIFICATE REQUEST",
		Bytes: der,
	}

	// write out PEM block to file
	csrFile, err := os.OpenFile(fileName, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0644)
	if err != nil {
		return block, fmt.Errorf("while opening %s for writing: %s", fileName, err)
	}
	if err := pem.Encode(csrFile, block); err != nil {
		csrFile.Close()
		return block, fmt.Errorf("failed to write data to %s: %s", fileName, err)
	}
	if err := csrFile.Close(); err != nil {
		return block, fmt.Errorf("while closing %s: %s", fileName, err)
	}

	return
}

func WriteCert(fileName string, cert []byte) (err error) {
	certFile, err := os.OpenFile(fileName, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0644)
	if err != nil {
		return
	}
	_, err = certFile.Write(cert)
	if err != nil {
		return
	}
	fmt.Printf("wrote %s\n", fileName)

	if err := certFile.Close(); err != nil {
		return fmt.Errorf("while closing %s: %s", fileName, err)
	}

	return
}