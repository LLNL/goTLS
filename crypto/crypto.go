// Copyright © 2019 Lawrence Livermore National Security, LLC
// SPDX-License-Identifier: MIT
// See top-level LICENSE file for details.

package crypto

import (
	"crypto/dsa"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/pem"
	"fmt"
	"net"
	"os"
	"strings"
)

type BasicConstraints struct {
	IsCA bool `asn1:"optional"`
}

func GetKey(fileName string, rsaSize int, verbose bool) (key any, err error) {
	// check for existing key
	if _, err = os.Stat(fileName); err == nil { // key exists
		if verbose {
			fmt.Printf("loading existing private key from %s\n", fileName)
		}
		keyBytes, innerErr := os.ReadFile(fileName)
		if innerErr != nil {
			return key, fmt.Errorf("while opening %s for reading: %s", fileName, innerErr)
		}

		block, _ := pem.Decode(keyBytes)
		if block == nil || !strings.HasSuffix(block.Type, "PRIVATE KEY") {
			return key, fmt.Errorf("could not parse PEM block with type ending in PRIVATE KEY")
		}

		// attempt to parse any private key type
		success := false
		keyType := ""
		containerType := ""
		if key, err = x509.ParsePKCS1PrivateKey(block.Bytes); err == nil { // PKCS#1 RSA key
			success = true
			keyType = "RSA"
			containerType = "PKCS#1"
		}
		if !success {
			if key, err = x509.ParsePKCS8PrivateKey(block.Bytes); err == nil { // PKCS#8 key
				success = true
				containerType = "PKCS#8"
				switch key := key.(type) {
				case *rsa.PrivateKey:
					err = (*rsa.PrivateKey)(key).Validate()
					if err != nil {
						return nil, fmt.Errorf("invalid key: %s\n", err)
					}
					keyType = "RSA"
				case *dsa.PrivateKey:
					keyType = "DSA"
				case *ecdsa.PrivateKey:
					keyType = "ECDSA"
				case ed25519.PrivateKey:
					keyType = "Ed25519"
				default:
					return nil, fmt.Errorf("could not parse private key in PKCS#8 format")
				}
			}
		}
		if !success {
			if key, err = x509.ParseECPrivateKey(block.Bytes); err == nil { // SEC 1 ECSDA key
				keyType = "ECDSA"
				containerType = "SEC 1"
			}
		}
		if !success {
			return nil, fmt.Errorf("could not parse private key: invalid/unrecognized key format")
		}
		if verbose {
			fmt.Printf("read %s key in %s format\n", keyType, containerType)
		}
	} else {
		if verbose {
			fmt.Printf("Generating new private key\n")
		}
		// generate private key
		genkey, err := rsa.GenerateKey(rand.Reader, rsaSize)
		if err != nil {
			return nil, err
		}

		// get PEM block for private key
		block := &pem.Block{
			Type:  "RSA PRIVATE KEY",
			Bytes: x509.MarshalPKCS1PrivateKey(genkey),
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

		fmt.Printf("wrote private key to %s\n", fileName)

		return genkey, nil
	}

	return
}

func GenerateCsr(fileName string, key any, cn, c, st, l, o, ou, email string, dns []string, ips []net.IP) (block *pem.Block, err error) {
	// populate subject fields (designating CN as required)
	subject := pkix.Name{
		CommonName: cn,
	}
	if c != "" {
		subject.Country = []string{c}
	}
	if st != "" {
		subject.Province = []string{st}
	}
	if l != "" {
		subject.Locality = []string{l}
	}
	if o != "" {
		subject.Organization = []string{o}
	}
	if ou != "" {
		subject.OrganizationalUnit = []string{ou}
	}
	if email != "" {
		// using subject.EmailAddresses would set the email in the SAN field (for email certificates)
		subject.ExtraNames = []pkix.AttributeTypeAndValue{
			pkix.AttributeTypeAndValue{
				Type: asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 1},
				Value: asn1.RawValue{
					Tag:   asn1.TagIA5String,
					Bytes: []byte(email),
				},
			},
		}
	}
	//TODO: StreetAddress
	//TODO: PostalCode

	basicConstraints, err := asn1.Marshal(BasicConstraints{false})
	if err != nil {
		return block, fmt.Errorf("could not encode CA constraint into asn1 format: %s", err)
	}

	// populate CSR template
	template := &x509.CertificateRequest{
		SignatureAlgorithm: x509.SHA256WithRSA,
		Subject:            subject,
		ExtraExtensions: []pkix.Extension{
			// key usage
			pkix.Extension{
				Id:       asn1.ObjectIdentifier{2, 5, 29, 15},
				Critical: false,
				Value:    []byte{0x03, 0x02, 0x03, 0xe0}, // 0x03: 3 bits; 0xe0: digitalSignature(0),nonRepudiation(1),keyEncipherment(2)
			},
			// Basic constraint: CA=false
			pkix.Extension{
				Id:       asn1.ObjectIdentifier{2, 5, 29, 19},
				Critical: false,
				Value:    basicConstraints,
			},
		},
	}
	if len(dns) > 0 {
		template.DNSNames = dns
	}
	if len(ips) > 0 {
		template.IPAddresses = ips
	}

	// create CSR
	der, err := x509.CreateCertificateRequest(rand.Reader, template, key)
	if err != nil {
		return
	}

	// get PEM block for CSR
	block = &pem.Block{
		Type:  "CERTIFICATE REQUEST",
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
