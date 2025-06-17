// Copyright © 2019 Lawrence Livermore National Security, LLC
// SPDX-License-Identifier: MIT
// See top-level LICENSE file for details.

package crypto

import (
	"crypto/dsa"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
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

// type representing a private key container format
type KeyContainer int

const (
	UnknownKeyContainer KeyContainer = iota
	PKCS1
	PKCS8
	SEC1
)

func (kc KeyContainer) String() string {
	switch kc {
	case PKCS1:
		return "PKCS#1"
	case PKCS8:
		return "PKCS#8"
	case SEC1:
		return "SEC 1"
	default:
		return "unknown container"
	}
}

// type representing a NIST Elliptic Curve implementation
type EcSize int

const (
	UnknownEcSize EcSize = iota
	P224
	P256
	P384
	P521
)

func (ec EcSize) String() string {
	switch ec {
	case P224:
		return "P-224/secp224r1"
	case P256:
		return "P-256/secp256r1"
	case P384:
		return "P-384/secp384r1"
	case P521:
		return "P-521/secp521r1"
	default:
		return "unknown EC size"
	}
}

type KeyRequest struct {
	Filename  string
	Type      x509.PublicKeyAlgorithm
	Container KeyContainer
	EcSize    EcSize
	RsaSize   int
}

type BasicConstraints struct {
	IsCA bool `asn1:"optional"`
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
		return nil, fmt.Errorf("could not encode CA constraint into asn1 format: %w", err)
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
		return nil, err
	}

	// get PEM block for CSR
	block = &pem.Block{
		Type:  "CERTIFICATE REQUEST",
		Bytes: der,
	}

	// write out PEM block to file
	csrFile, err := os.OpenFile(fileName, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0644)
	if err != nil {
		return block, fmt.Errorf("could not open file for writing: %w", err)
	}
	if err := pem.Encode(csrFile, block); err != nil {
		csrFile.Close()
		return block, fmt.Errorf("could not write data: %w", err)
	}
	if err := csrFile.Close(); err != nil {
		return block, fmt.Errorf("could not close file: %w", err)
	}

	return block, nil
}

// generates a private key given key attributes or returns an error
func GenerateKey(keyRequest *KeyRequest) (key any, err error) {
	switch keyRequest.Type {
	case x509.DSA:
		//TODO: allow --force option?
		err = fmt.Errorf(
			"DSA key generation is not allowed due to legacy algorithm. Use %s, %s, or %s algorithms.",
			x509.RSA.String(),
			x509.ECDSA.String(),
			x509.Ed25519.String(),
		)
	case x509.RSA:
		key, err = rsa.GenerateKey(rand.Reader, keyRequest.RsaSize)
	case x509.ECDSA:
		switch keyRequest.EcSize {
		case P224:
			key, err = ecdsa.GenerateKey(elliptic.P224(), rand.Reader)
		case P256:
			key, err = ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		case P384:
			key, err = ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
		case P521:
			key, err = ecdsa.GenerateKey(elliptic.P521(), rand.Reader)
		default:
			return key, fmt.Errorf("elliptic curve key implementations are limited to %s, %s, %s, or %s",
				P224.String(), P256.String(), P384.String(), P521.String())
		}
	case x509.Ed25519:
		_, key, err = ed25519.GenerateKey(rand.Reader)
	}

	return key, err
}

// returns a private key from an existing file (an instance of the crypto/rsa, dsa, ecdsa, or ed25519 types) or an error
func GetKey(keyRequest *KeyRequest) (key any, err error) {
	keyBytes, innerErr := os.ReadFile(keyRequest.Filename)
	if innerErr != nil {
		return nil, fmt.Errorf("could not read file: %w", innerErr)
	}

	block, _ := pem.Decode(keyBytes)
	if block == nil || !strings.HasSuffix(block.Type, "PRIVATE KEY") {
		return nil, fmt.Errorf("could not parse PEM block with type ending in PRIVATE KEY")
	}

	// attempt to parse any private key type
	success := false
	if key, err = x509.ParsePKCS1PrivateKey(block.Bytes); err == nil { // PKCS1 RSA key
		success = true
		keyRequest.Type = x509.RSA
		keyRequest.Container = PKCS1
	}
	if !success {
		if key, err = x509.ParsePKCS8PrivateKey(block.Bytes); err == nil { // PKCS8 key
			success = true
			keyRequest.Container = PKCS8
			switch key := key.(type) {
			case *rsa.PrivateKey:
				err = (*rsa.PrivateKey)(key).Validate()
				if err != nil {
					return nil, fmt.Errorf("invalid key: %w", err)
				}
				keyRequest.Type = x509.RSA
			case *dsa.PrivateKey:
				keyRequest.Type = x509.DSA
			case *ecdsa.PrivateKey:
				keyRequest.Type = x509.ECDSA
			case ed25519.PrivateKey:
				keyRequest.Type = x509.Ed25519
			default:
				return nil, fmt.Errorf("could not parse private key in %s format", PKCS8.String())
			}
		}
	}
	if !success {
		if key, err = x509.ParseECPrivateKey(block.Bytes); err == nil { // SEC1 ECSDA key
			keyRequest.Type = x509.ECDSA
			keyRequest.Container = SEC1
		}
	}
	if !success {
		return nil, fmt.Errorf("could not parse private key: invalid/unrecognized key format")
	}

	return
}

// writes a certificate to a file or returns an error
func WriteCert(filename string, cert []byte) (err error) {
	certFile, err := os.OpenFile(filename, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0644)
	if err != nil {
		return fmt.Errorf("could not open file for writing: %w", err)
	}
	_, err = certFile.Write(cert)
	if err != nil {
		return fmt.Errorf("could not write data: %w", err)
	}

	if err := certFile.Close(); err != nil {
		return fmt.Errorf("could not close file: %w", err)
	}

	return nil
}

// writes a private key to a file with the given filename or returns an error
func WriteKey(key any, keyRequest *KeyRequest) (err error) {
	var block *pem.Block

	// get PEM block for private key
	if keyRequest.Container == PKCS1 {
		if keyRequest.Type == x509.RSA {
			// RSA keys must be validated first
			rsaKey, ok := key.(*rsa.PrivateKey)
			if !ok {
				return fmt.Errorf("key is not an %s key", x509.RSA.String())
			}
			err = rsaKey.Validate()
			if err != nil {
				return fmt.Errorf("could not validate %s key: %w", x509.RSA.String(), err)
			}

			block = &pem.Block{
				Type:  "RSA PRIVATE KEY",
				Bytes: x509.MarshalPKCS1PrivateKey(rsaKey),
			}
		} else {
			return fmt.Errorf("only %s keys are supported in %s containers", x509.RSA.String(), PKCS8.String())
		}
	} else if keyRequest.Container == PKCS8 {
		bytes, err := x509.MarshalPKCS8PrivateKey(key)
		if err != nil {
			return fmt.Errorf("could not encode key: %w", err)
		}

		block = &pem.Block{
			Type:  "PRIVATE KEY",
			Bytes: bytes,
		}
	} else if keyRequest.Container == SEC1 {
		if keyRequest.Type == x509.ECDSA {
			ecdsaKey, ok := key.(*ecdsa.PrivateKey)
			if !ok {
				return fmt.Errorf("key is not an %s key", x509.ECDSA.String())
			}

			bytes, err := x509.MarshalECPrivateKey(ecdsaKey)
			if err != nil {
				return fmt.Errorf("could not encode key: %w", err)
			}

			block = &pem.Block{
				Type:  "EC PRIVATE KEY",
				Bytes: bytes,
			}
		} else {
			return fmt.Errorf("only %s keys are supported in %s containers", x509.ECDSA.String(), SEC1.String())
		}
	}

	// open destination file
	keyFile, err := os.OpenFile(keyRequest.Filename, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0600)
	if err != nil {
		return fmt.Errorf("could not open file for writing: %w", err)
	}

	// write out PEM block to file
	if err = pem.Encode(keyFile, block); err != nil {
		keyFile.Close()
		return fmt.Errorf("could not write data: %w", err)
	}

	// close destination file
	if err = keyFile.Close(); err != nil {
		return fmt.Errorf("could not close file: %w", err)
	}

	return nil
}
