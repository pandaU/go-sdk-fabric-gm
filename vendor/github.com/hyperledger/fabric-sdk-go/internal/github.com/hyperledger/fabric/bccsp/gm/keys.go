/*
Copyright IBM Corp. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/
package gm

import (
	"crypto/x509"
	"encoding/pem"
	"fmt"

	x509GM "github.com/Hyperledger-TWGC/tjfoc-gm/x509"
	"github.com/pkg/errors"
)

func derToPrivateKey(der []byte) (key interface{}, err error) {
	if key, err = x509GM.ParsePKCS8UnecryptedPrivateKey(der); err == nil {
		return key, nil
	}

	if key, err = x509GM.ParseSm2PrivateKey(der); err == nil {
		return key, nil
	}
	return nil, errors.New("Invalid key type. The DER must contain an rsa.PrivateKey or ecdsa.PrivateKey")
}

func pemToPrivateKey(raw []byte, pwd []byte) (interface{}, error) {
	block, _ := pem.Decode(raw)
	if block == nil {
		return nil, fmt.Errorf("failed decoding PEM. Block must be different from nil [% x]", raw)
	}

	// TODO: derive from header the type of the key

	if x509.IsEncryptedPEMBlock(block) {
		if len(pwd) == 0 {
			return nil, errors.New("encrypted Key. Need a password")
		}

		decrypted, err := x509.DecryptPEMBlock(block, pwd)
		if err != nil {
			return nil, fmt.Errorf("failed PEM decryption: [%s]", err)
		}

		key, err := derToPrivateKey(decrypted)
		if err != nil {
			return nil, err
		}
		return key, err
	}

	cert, err := derToPrivateKey(block.Bytes)
	if err != nil {
		return nil, err
	}
	return cert, err
}
