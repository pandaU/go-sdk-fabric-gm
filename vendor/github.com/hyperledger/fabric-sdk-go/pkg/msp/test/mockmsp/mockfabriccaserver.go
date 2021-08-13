/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package mockmsp

import (
	"net"
	"net/http"
	"time"

	cfsslapi "github.com/cloudflare/cfssl/api"
	"github.com/hyperledger/fabric-sdk-go/internal/github.com/hyperledger/fabric-ca/lib"
	"github.com/hyperledger/fabric-sdk-go/internal/github.com/hyperledger/fabric-ca/sdkinternal/pkg/api"
	"github.com/hyperledger/fabric-sdk-go/internal/github.com/hyperledger/fabric-ca/sdkinternal/pkg/util"
	"github.com/hyperledger/fabric-sdk-go/pkg/common/logging"
	"github.com/hyperledger/fabric-sdk-go/pkg/common/providers/core"
)

// Matching key-cert pair. On enroll, the key will be
// imported into the key store, and the cert will be
// returned to the caller.
const privateKey = `-----BEGIN PRIVATE KEY-----
MIGHAgEAMBMGByqGSM49AgEGCCqBHM9VAYItBG0wawIBAQQg95NZf7A5P1oQRZhC
Ox28tf3oDZ3/6VxVGBTC5Tcp9JehRANCAASGEZFG4wypmaCJT+lBAWCV2FkfUbw7
RvwAd0aMmnnbpaA8d8dUS2eVZM8L8xEaEdZS+7cq1BkLomNlhunZHlOO
-----END PRIVATE KEY-----`

const ecert = `-----BEGIN CERTIFICATE-----
MIICVTCCAfugAwIBAgICEAAwCgYIKoEcz1UBg3UwTTELMAkGA1UEBhMCQ04xEjAQ
BgNVBAgMCVNoYW5nIEhhaTEUMBIGA1UECgwLZXhhbXBsZS5jb20xFDASBgNVBAMM
C2V4YW1wbGUuY29tMB4XDTIwMTEwNjAzNDcxOFoXDTIxMTEwNjAzNDcxOFowUjEL
MAkGA1UEBhMCQ04xEjAQBgNVBAgMCVNoYW5nIEhhaTEUMBIGA1UECgwLZXhhbXBs
ZS5jb20xGTAXBgNVBAMMEHRlc3QuZXhhbXBsZS5jb20wWTATBgcqhkjOPQIBBggq
gRzPVQGCLQNCAASGEZFG4wypmaCJT+lBAWCV2FkfUbw7RvwAd0aMmnnbpaA8d8dU
S2eVZM8L8xEaEdZS+7cq1BkLomNlhunZHlOOo4HFMIHCMAkGA1UdEwQCMAAwEQYJ
YIZIAYb4QgEBBAQDAgWgMDMGCWCGSAGG+EIBDQQmFiRPcGVuU1NMIEdlbmVyYXRl
ZCBDbGllbnQgQ2VydGlmaWNhdGUwHQYDVR0OBBYEFFCF9vkoz5PtgG9GLrtwhudu
pXnBMB8GA1UdIwQYMBaAFDM+RncxHLMVJbqqtpGiySBY/TQpMA4GA1UdDwEB/wQE
AwIF4DAdBgNVHSUEFjAUBggrBgEFBQcDAgYIKwYBBQUHAwQwCgYIKoEcz1UBg3UD
SAAwRQIhANTmjw2HoebvRehFbxs07kpxy6BcFq9VBj09bbTNMPGoAiBG2NgyyJNE
fzc+unAvES06xZrBlUUbiaKTITvQKcJJVQ==
-----END CERTIFICATE-----`

var logger = logging.NewLogger("fabsdk/msp")

// The enrollment response from the server
type enrollmentResponseNet struct {
	// Base64 encoded PEM-encoded ECert
	Cert string
	// The server information
	ServerInfo serverInfoResponseNet
}

// The response to the GET /info request
type serverInfoResponseNet struct {
	// CAName is a unique name associated with fabric-ca-server's CA
	CAName string
	// Base64 encoding of PEM-encoded certificate chain
	CAChain string
}

// MockFabricCAServer is a mock for FabricCAServer
type MockFabricCAServer struct {
	address     string
	cryptoSuite core.CryptoSuite
	running     bool
}

// Start fabric CA mock server
func (s *MockFabricCAServer) Start(lis net.Listener, cryptoSuite core.CryptoSuite) {

	if s.running {
		panic("already started")
	}

	addr := lis.Addr().String()
	s.address = addr
	s.cryptoSuite = cryptoSuite

	// Register request handlers

	http.HandleFunc("/register", s.register)
	http.HandleFunc("/enroll", s.enroll)
	http.HandleFunc("/reenroll", s.enroll)
	http.HandleFunc("/revoke", s.revoke)
	http.HandleFunc("/identities", s.identities)
	http.HandleFunc("/identities/123", s.identity)
	http.HandleFunc("/affiliations", s.affiliations)
	http.HandleFunc("/affiliations/123", s.affiliation)
	http.HandleFunc("/cainfo", s.cainfo)

	server := &http.Server{
		Addr:      addr,
		TLSConfig: nil,
	}

	go func() {
		err := server.Serve(lis)
		if err != nil {
			panic("HTTP Server: Failed to start")
		}
	}()
	time.Sleep(1 * time.Second)
	logger.Debugf("HTTP Server started on %s", s.address)

	s.running = true

}

// Running returns the status of the mock server
func (s *MockFabricCAServer) Running() bool {
	return s.running
}

func (s *MockFabricCAServer) addKeyToKeyStore(privateKey []byte) error {
	// Import private key that matches the cert we will return
	// from this mock service, so it can be looked up by SKI from the cert
	_, err := util.ImportBCCSPKeyFromPEMBytes(privateKey, s.cryptoSuite, false)
	return err
}

// Register user
func (s *MockFabricCAServer) register(w http.ResponseWriter, req *http.Request) {
	resp := &api.RegistrationResponseNet{RegistrationResponse: api.RegistrationResponse{Secret: "mockSecretValue"}}
	if err := cfsslapi.SendResponse(w, resp); err != nil {
		logger.Error(err)
	}
}

// Revoke user
func (s *MockFabricCAServer) revoke(w http.ResponseWriter, req *http.Request) {
	resp := &api.RevocationResponse{}
	if err := cfsslapi.SendResponse(w, resp); err != nil {
		logger.Error(err)
	}
}

// Enroll user
func (s *MockFabricCAServer) enroll(w http.ResponseWriter, req *http.Request) {
	if err := s.addKeyToKeyStore([]byte(privateKey)); err != nil {
		logger.Error(err)
	}
	resp := &enrollmentResponseNet{Cert: util.B64Encode([]byte(ecert))}
	fillCAInfo(&resp.ServerInfo)
	if err := cfsslapi.SendResponse(w, resp); err != nil {
		logger.Error(err)
	}
}

// Fill the CA info structure appropriately
func fillCAInfo(info *serverInfoResponseNet) {
	info.CAName = "MockCAName"
	info.CAChain = util.B64Encode([]byte("MockCAChain"))
}

// Register user
func (s *MockFabricCAServer) identity(w http.ResponseWriter, req *http.Request) {
	switch req.Method {
	case http.MethodGet:
		// Serve the resource.
		resp := &api.GetIDResponse{ID: "123", Affiliation: "org2",
			Attributes: []api.Attribute{{Name: "attName1", Value: "attValue1"}, {Name: "attName2", Value: "attValue2"}}}
		if err := cfsslapi.SendResponse(w, resp); err != nil {
			logger.Error(err)
		}
	case http.MethodPut:
		// Update an existing record.
		resp := &api.IdentityResponse{ID: "123", Affiliation: "org2", Secret: "new-top-secret"}
		if err := cfsslapi.SendResponse(w, resp); err != nil {
			logger.Error(err)
		}
	case http.MethodDelete:
		// Remove the record.
		resp := &api.IdentityResponse{ID: "123"}
		if err := cfsslapi.SendResponse(w, resp); err != nil {
			logger.Error(err)
		}
	default:
		// Give an error message
		logger.Error("Request method not supported ")
	}

}

// Handler for creating an identity and retrieving all identities
func (s *MockFabricCAServer) identities(w http.ResponseWriter, req *http.Request) {
	switch req.Method {
	case http.MethodPost:
		// Create a new record.
		resp := &api.IdentityResponse{ID: "123", Affiliation: "org2", Secret: "top-secret"}
		if err := cfsslapi.SendResponse(w, resp); err != nil {
			logger.Error(err)
		}
	case http.MethodGet:
		// Serve the resource.
		resp := &api.GetAllIDsResponse{Identities: []api.IdentityInfo{{ID: "123", Affiliation: "org2"},
			{ID: "abc", Affiliation: "org2", Attributes: []api.Attribute{{Name: "attName1", Value: "attValue1"}}}}}
		if err := cfsslapi.SendResponse(w, resp); err != nil {
			logger.Error(err)
		}
	default:
		// Give an error message
		logger.Error("Request method not supported ")
	}

}

func (s *MockFabricCAServer) affiliations(w http.ResponseWriter, req *http.Request) {
	switch req.Method {
	case http.MethodPost:
		resp := &api.AffiliationResponse{AffiliationInfo: api.AffiliationInfo{Name: "test1.com"}}
		if err := cfsslapi.SendResponse(w, resp); err != nil {
			logger.Error(err)
		}

	case http.MethodGet:
		affs := []api.AffiliationInfo{
			{
				Name: "com",
				Affiliations: []api.AffiliationInfo{
					{
						Name: "test1.com",
					},
				},
			},
		}

		resp := &api.AffiliationResponse{AffiliationInfo: api.AffiliationInfo{Name: "", Affiliations: affs}}
		if err := cfsslapi.SendResponse(w, resp); err != nil {
			logger.Error(err)
		}
	}
}

func (s *MockFabricCAServer) affiliation(w http.ResponseWriter, req *http.Request) {
	switch req.Method {
	case http.MethodGet:
		resp := &api.AffiliationResponse{AffiliationInfo: api.AffiliationInfo{Name: "test1.com"}}
		if err := cfsslapi.SendResponse(w, resp); err != nil {
			logger.Error(err)
		}

	case http.MethodPut:
		resp := &api.AffiliationResponse{AffiliationInfo: api.AffiliationInfo{Name: "test1new.com"}}
		if err := cfsslapi.SendResponse(w, resp); err != nil {
			logger.Error(err)
		}

	case http.MethodDelete:
		resp := &api.AffiliationResponse{AffiliationInfo: api.AffiliationInfo{Name: "test1.com"}}
		if err := cfsslapi.SendResponse(w, resp); err != nil {
			logger.Error(err)
		}
	}
}

func (s *MockFabricCAServer) cainfo(w http.ResponseWriter, req *http.Request) {
	switch req.Method {
	case http.MethodPost:
		resp := &lib.GetCAInfoResponse{CAName: "123", CAChain: []byte{}, Version: "1.4"}
		if err := cfsslapi.SendResponse(w, resp); err != nil {
			logger.Error(err)
		}
	}
}
