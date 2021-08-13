/*
Copyright IBM Corp. 2016 All Rights Reserved.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

                 http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/
/*
Notice: This file has been modified for Hyperledger Fabric SDK Go usage.
Please review third_party pinning scripts and patches for more details.
*/

package gmtls

import (
	"crypto/x509"
	"time"

	"github.com/Hyperledger-TWGC/tjfoc-gm/gmtls"
	x509GM "github.com/Hyperledger-TWGC/tjfoc-gm/x509"
	"github.com/hyperledger/fabric-sdk-go/internal/github.com/hyperledger/fabric-ca/sdkinternal/pkg/util"
	factory "github.com/hyperledger/fabric-sdk-go/internal/github.com/hyperledger/fabric-ca/sdkpatch/cryptosuitebridge"
	log "github.com/hyperledger/fabric-sdk-go/internal/github.com/hyperledger/fabric-ca/sdkpatch/logbridge"
	"github.com/hyperledger/fabric-sdk-go/pkg/common/providers/core"
	"github.com/pkg/errors"
)

// DefaultCipherSuites is a set of strong TLS cipher suites
var DefaultCipherSuites = []uint16{
	gmtls.GMTLS_SM2_WITH_SM4_SM3,
	gmtls.GMTLS_ECDHE_SM2_WITH_SM4_SM3,
}

// ClientTLSConfig defines the key material for a TLS client
type ClientTLSConfig struct {
	Enabled       bool     `skip:"true"`
	CertFiles     [][]byte `help:"A list of comma-separated PEM-encoded trusted certificate bytes"`
	Client        KeyCertFiles
	TlsCertPool   *x509.CertPool
	GmTlsCertPool *x509GM.CertPool
}

// KeyCertFiles defines the files need for client on TLS
type KeyCertFiles struct {
	KeyFile  []byte `help:"PEM-encoded key bytes when mutual authentication is enabled"`
	CertFile []byte `help:"PEM-encoded certificate bytes when mutual authenticate is enabled"`
}

// GetClientTLSConfig creates a gmtls.Config object from certs and roots
func GetClientTLSConfig(cfg *ClientTLSConfig, csp core.CryptoSuite) (*gmtls.Config, error) {
	var certs []gmtls.Certificate

	if csp == nil {
		csp = factory.GetDefault()
	}

	if cfg.Client.CertFile != nil {
		err := checkCertDates(cfg.Client.CertFile)
		if err != nil {
			return nil, err
		}

		clientCert, err := gmtls.X509KeyPair(cfg.Client.CertFile, cfg.Client.KeyFile)
		if err != nil {
			return nil, err
		}

		certs = append(certs, clientCert)
	} else {
		log.Debug("Client TLS certificate and/or key file not provided")
	}
	rootCAPool := cfg.GmTlsCertPool

	if rootCAPool == nil {
		rootCAPool, err := x509GM.SystemCertPool()
		if err != nil {
			log.Debugf("Failed to load system cert pool, switching to empty cert pool ")
			rootCAPool = x509GM.NewCertPool()
		}

		if len(cfg.CertFiles) == 0 {
			return nil, errors.New("No trusted root certificates for TLS were provided")
		}

		for _, cacert := range cfg.CertFiles {
			ok := rootCAPool.AppendCertsFromPEM(cacert)
			if !ok {
				return nil, errors.New("Failed to process certificate")
			}
		}
	}

	var gmSupport *gmtls.GMSupport
	if core.IsGMCryptoSuite(csp) {
		gmSupport = &gmtls.GMSupport{}
	}

	config := &gmtls.Config{
		GMSupport:    gmSupport,
		Certificates: certs,
		RootCAs:      rootCAPool,
	}

	return config, nil
}

func checkCertDates(certPEM []byte) error {
	log.Debug("Check client TLS certificate for valid dates")

	cert, err := util.GetX509CertificateFromPEM(certPEM)
	if err != nil {
		return err
	}

	notAfter := cert.NotAfter
	currentTime := time.Now().UTC()

	if currentTime.After(notAfter) {
		return errors.New("Certificate provided has expired")
	}

	notBefore := cert.NotBefore
	if currentTime.Before(notBefore) {
		return errors.New("Certificate provided not valid until later date")
	}

	return nil
}
