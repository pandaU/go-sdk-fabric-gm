/*
Copyright IBM Corp. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package factory

import (
	"fmt"

	"github.com/hyperledger/fabric-sdk-go/internal/github.com/hyperledger/fabric/bccsp"
	"github.com/hyperledger/fabric-sdk-go/internal/github.com/hyperledger/fabric/bccsp/gm"
)

const (
	// GuomiBasedFactoryName is the name of the factory of the software-based BCCSP implementation
	GuomiBasedFactoryName = "GM"
)

// GMFactory is the factory of the guomi-based BCCSP.
type GMFactory struct{}

// Name returns the name of this factory
func (f *GMFactory) Name() string {
	return GuomiBasedFactoryName
}

// Pluggable Keystores, could add JKS, P12, etc..
type FileKeystoreOpts struct {
	KeyStorePath string `mapstructure:"keystore" yaml:"KeyStore"`
}

type DummyKeystoreOpts struct{}

// InmemKeystoreOpts - empty, as there is no config for the in-memory keystore
type InmemKeystoreOpts struct{}

type GmOpts struct {
	// Default algorithms when not specified (Deprecated?)
	SecLevel   int    `mapstructure:"security" json:"security" yaml:"Security"`
	HashFamily string `mapstructure:"hash" json:"hash" yaml:"Hash"`

	// Keystore Options
	Ephemeral     bool               `mapstructure:"tempkeys,omitempty" json:"tempkeys,omitempty"`
	FileKeystore  *FileKeystoreOpts  `mapstructure:"filekeystore,omitempty" json:"filekeystore,omitempty" yaml:"FileKeyStore"`
	DummyKeystore *DummyKeystoreOpts `mapstructure:"dummykeystore,omitempty" json:"dummykeystore,omitempty"`
	InmemKeystore *InmemKeystoreOpts `mapstructure:"inmemkeystore,omitempty" json:"inmemkeystore,omitempty"`
}

// Get returns an instance of BCCSP using Opts.
func (f *GMFactory) Get(gmOpts *GmOpts) (bccsp.BCCSP, error) {

	var ks bccsp.KeyStore
	if gmOpts.Ephemeral == true {
		ks = gm.NewDummyKeyStore()
	} else if gmOpts.FileKeystore != nil {
		fks, err := gm.NewFileBasedKeyStore(nil, gmOpts.FileKeystore.KeyStorePath, false)
		if err != nil {
			return nil, fmt.Errorf("Failed to initialize gm software key store: %s", err)
		}
		ks = fks
	} else {
		// Default to DummyKeystore
		ks = gm.NewDummyKeyStore()
	}

	csp, err := gm.New(ks)
	return csp, err
}
