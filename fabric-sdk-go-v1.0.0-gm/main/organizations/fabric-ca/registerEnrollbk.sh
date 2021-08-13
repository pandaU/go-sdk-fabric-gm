#/bin/bash

function createOrg1() {
  infoln "Enrolling the CA admin"
  mkdir -p organizations/peerOrganizations/org1.xxzx.com/

  export FABRIC_CA_CLIENT_HOME=${PWD}/organizations/peerOrganizations/org1.xxzx.com/

  set -x
  fabric-ca-client enroll -u https://admin:adminpw@localhost:7054 --caname ca-org1 --tls.certfiles ${PWD}/organizations/fabric-ca/org1/tls-cert.pem
  { set +x; } 2>/dev/null

  echo 'NodeOUs:
  Enable: true
  ClientOUIdentifier:
    Certificate: cacerts/localhost-7054-ca-org1.pem
    OrganizationalUnitIdentifier: client
  PeerOUIdentifier:
    Certificate: cacerts/localhost-7054-ca-org1.pem
    OrganizationalUnitIdentifier: peer
  AdminOUIdentifier:
    Certificate: cacerts/localhost-7054-ca-org1.pem
    OrganizationalUnitIdentifier: admin
  OrdererOUIdentifier:
    Certificate: cacerts/localhost-7054-ca-org1.pem
    OrganizationalUnitIdentifier: orderer' >${PWD}/organizations/peerOrganizations/org1.xxzx.com/msp/config.yaml

  infoln "Registering peer0"
  set -x
  fabric-ca-client register --caname ca-org1 --id.name peer0 --id.secret peer0pw --id.type peer --tls.certfiles ${PWD}/organizations/fabric-ca/org1/tls-cert.pem
  { set +x; } 2>/dev/null

  infoln "Registering user"
  set -x
  fabric-ca-client register --caname ca-org1 --id.name user1 --id.secret user1pw --id.type client --tls.certfiles ${PWD}/organizations/fabric-ca/org1/tls-cert.pem
  { set +x; } 2>/dev/null

  infoln "Registering the org admin"
  set -x
  fabric-ca-client register --caname ca-org1 --id.name org1admin --id.secret org1adminpw --id.type admin --tls.certfiles ${PWD}/organizations/fabric-ca/org1/tls-cert.pem
  { set +x; } 2>/dev/null

  infoln "Generating the peer0 msp"
  set -x
  fabric-ca-client enroll -u https://peer0:peer0pw@localhost:7054 --caname ca-org1 -M ${PWD}/organizations/peerOrganizations/org1.xxzx.com/peers/peer0.org1.xxzx.com/msp --csr.hosts peer0.org1.xxzx.com --tls.certfiles ${PWD}/organizations/fabric-ca/org1/tls-cert.pem
  { set +x; } 2>/dev/null

  cp ${PWD}/organizations/peerOrganizations/org1.xxzx.com/msp/config.yaml ${PWD}/organizations/peerOrganizations/org1.xxzx.com/peers/peer0.org1.xxzx.com/msp/config.yaml

  infoln "Generating the peer0-tls certificates"
  set -x
  fabric-ca-client enroll -u https://peer0:peer0pw@localhost:7054 --caname ca-org1 -M ${PWD}/organizations/peerOrganizations/org1.xxzx.com/peers/peer0.org1.xxzx.com/tls --enrollment.profile tls --csr.hosts peer0.org1.xxzx.com --csr.hosts localhost --tls.certfiles ${PWD}/organizations/fabric-ca/org1/tls-cert.pem
  { set +x; } 2>/dev/null

  cp ${PWD}/organizations/peerOrganizations/org1.xxzx.com/peers/peer0.org1.xxzx.com/tls/tlscacerts/* ${PWD}/organizations/peerOrganizations/org1.xxzx.com/peers/peer0.org1.xxzx.com/tls/ca.crt
  cp ${PWD}/organizations/peerOrganizations/org1.xxzx.com/peers/peer0.org1.xxzx.com/tls/signcerts/* ${PWD}/organizations/peerOrganizations/org1.xxzx.com/peers/peer0.org1.xxzx.com/tls/server.crt
  cp ${PWD}/organizations/peerOrganizations/org1.xxzx.com/peers/peer0.org1.xxzx.com/tls/keystore/* ${PWD}/organizations/peerOrganizations/org1.xxzx.com/peers/peer0.org1.xxzx.com/tls/server.key

  mkdir -p ${PWD}/organizations/peerOrganizations/org1.xxzx.com/msp/tlscacerts
  cp ${PWD}/organizations/peerOrganizations/org1.xxzx.com/peers/peer0.org1.xxzx.com/tls/tlscacerts/* ${PWD}/organizations/peerOrganizations/org1.xxzx.com/msp/tlscacerts/ca.crt

  mkdir -p ${PWD}/organizations/peerOrganizations/org1.xxzx.com/tlsca
  cp ${PWD}/organizations/peerOrganizations/org1.xxzx.com/peers/peer0.org1.xxzx.com/tls/tlscacerts/* ${PWD}/organizations/peerOrganizations/org1.xxzx.com/tlsca/tlsca.org1.xxzx.com-cert.pem

  mkdir -p ${PWD}/organizations/peerOrganizations/org1.xxzx.com/ca
  cp ${PWD}/organizations/peerOrganizations/org1.xxzx.com/peers/peer0.org1.xxzx.com/msp/cacerts/* ${PWD}/organizations/peerOrganizations/org1.xxzx.com/ca/ca.org1.xxzx.com-cert.pem

  infoln "Generating the user msp"
  set -x
  fabric-ca-client enroll -u https://user1:user1pw@localhost:7054 --caname ca-org1 -M ${PWD}/organizations/peerOrganizations/org1.xxzx.com/users/User1@org1.xxzx.com/msp --tls.certfiles ${PWD}/organizations/fabric-ca/org1/tls-cert.pem
  { set +x; } 2>/dev/null

  cp ${PWD}/organizations/peerOrganizations/org1.xxzx.com/msp/config.yaml ${PWD}/organizations/peerOrganizations/org1.xxzx.com/users/User1@org1.xxzx.com/msp/config.yaml

  infoln "Generating the org admin msp"
  set -x
  fabric-ca-client enroll -u https://org1admin:org1adminpw@localhost:7054 --caname ca-org1 -M ${PWD}/organizations/peerOrganizations/org1.xxzx.com/users/Admin@org1.xxzx.com/msp --tls.certfiles ${PWD}/organizations/fabric-ca/org1/tls-cert.pem
  { set +x; } 2>/dev/null

  cp ${PWD}/organizations/peerOrganizations/org1.xxzx.com/msp/config.yaml ${PWD}/organizations/peerOrganizations/org1.xxzx.com/users/Admin@org1.xxzx.com/msp/config.yaml
}

function createOrderer() {
  infoln "Enrolling the CA admin"
  mkdir -p organizations/ordererOrganizations/xxzx.com

  export FABRIC_CA_CLIENT_HOME=${PWD}/organizations/ordererOrganizations/xxzx.com

  set -x
  fabric-ca-client enroll -u https://admin:adminpw@localhost:9054 --caname ca-orderer --tls.certfiles ${PWD}/organizations/fabric-ca/ordererOrg/tls-cert.pem
  { set +x; } 2>/dev/null

  echo 'NodeOUs:
  Enable: true
  ClientOUIdentifier:
    Certificate: cacerts/localhost-9054-ca-orderer.pem
    OrganizationalUnitIdentifier: client
  PeerOUIdentifier:
    Certificate: cacerts/localhost-9054-ca-orderer.pem
    OrganizationalUnitIdentifier: peer
  AdminOUIdentifier:
    Certificate: cacerts/localhost-9054-ca-orderer.pem
    OrganizationalUnitIdentifier: admin
  OrdererOUIdentifier:
    Certificate: cacerts/localhost-9054-ca-orderer.pem
    OrganizationalUnitIdentifier: orderer' >${PWD}/organizations/ordererOrganizations/xxzx.com/msp/config.yaml

  infoln "Registering orderer"
  set -x
  fabric-ca-client register --caname ca-orderer --id.name orderer --id.secret ordererpw --id.type orderer --tls.certfiles ${PWD}/organizations/fabric-ca/ordererOrg/tls-cert.pem
  { set +x; } 2>/dev/null
  
  set -x
  fabric-ca-client register --caname ca-orderer --id.name orderer1 --id.secret orderer1pw --id.type orderer --tls.certfiles ${PWD}/organizations/fabric-ca/ordererOrg/tls-cert.pem
  { set +x; } 2>/dev/null

    set -x
  fabric-ca-client register --caname ca-orderer --id.name orderer2 --id.secret orderer2pw --id.type orderer --tls.certfiles ${PWD}/organizations/fabric-ca/ordererOrg/tls-cert.pem
  { set +x; } 2>/dev/null

  infoln "Registering the orderer admin"
  set -x
  fabric-ca-client register --caname ca-orderer --id.name ordererAdmin --id.secret ordererAdminpw --id.type admin --tls.certfiles ${PWD}/organizations/fabric-ca/ordererOrg/tls-cert.pem
  { set +x; } 2>/dev/null

  infoln "Generating the orderer msp"
  set -x
  fabric-ca-client enroll -u https://orderer:ordererpw@localhost:9054 --caname ca-orderer -M ${PWD}/organizations/ordererOrganizations/xxzx.com/orderers/orderer.xxzx.com/msp --csr.hosts orderer.xxzx.com --csr.hosts localhost --tls.certfiles ${PWD}/organizations/fabric-ca/ordererOrg/tls-cert.pem
  { set +x; } 2>/dev/null

  cp ${PWD}/organizations/ordererOrganizations/xxzx.com/msp/config.yaml ${PWD}/organizations/ordererOrganizations/xxzx.com/orderers/orderer.xxzx.com/msp/config.yaml

  set -x
  fabric-ca-client enroll -u https://orderer1:orderer1pw@localhost:9054 --caname ca-orderer -M ${PWD}/organizations/ordererOrganizations/xxzx.com/orderers/orderer1.xxzx.com/msp --csr.hosts orderer1.xxzx.com --csr.hosts localhost --tls.certfiles ${PWD}/organizations/fabric-ca/ordererOrg/tls-cert.pem
  { set +x; } 2>/dev/null

  cp ${PWD}/organizations/ordererOrganizations/xxzx.com/msp/config.yaml ${PWD}/organizations/ordererOrganizations/xxzx.com/orderers/orderer1.xxzx.com/msp/config.yaml


   set -x
  fabric-ca-client enroll -u https://orderer2:orderer2pw@localhost:9054 --caname ca-orderer -M ${PWD}/organizations/ordererOrganizations/xxzx.com/orderers/orderer2.xxzx.com/msp --csr.hosts orderer2.xxzx.com --csr.hosts localhost --tls.certfiles ${PWD}/organizations/fabric-ca/ordererOrg/tls-cert.pem
  { set +x; } 2>/dev/null

  cp ${PWD}/organizations/ordererOrganizations/xxzx.com/msp/config.yaml ${PWD}/organizations/ordererOrganizations/xxzx.com/orderers/orderer2.xxzx.com/msp/config.yaml 

 infoln "Generating the orderer-tls certificates"
  set -x
  fabric-ca-client enroll -u https://orderer:ordererpw@localhost:9054 --caname ca-orderer -M ${PWD}/organizations/ordererOrganizations/xxzx.com/orderers/orderer.xxzx.com/tls --enrollment.profile tls --csr.hosts orderer.xxzx.com --csr.hosts localhost --tls.certfiles ${PWD}/organizations/fabric-ca/ordererOrg/tls-cert.pem
  { set +x; } 2>/dev/null

  cp ${PWD}/organizations/ordererOrganizations/xxzx.com/orderers/orderer.xxzx.com/tls/tlscacerts/* ${PWD}/organizations/ordererOrganizations/xxzx.com/orderers/orderer.xxzx.com/tls/ca.crt
  cp ${PWD}/organizations/ordererOrganizations/xxzx.com/orderers/orderer.xxzx.com/tls/signcerts/* ${PWD}/organizations/ordererOrganizations/xxzx.com/orderers/orderer.xxzx.com/tls/server.crt
  cp ${PWD}/organizations/ordererOrganizations/xxzx.com/orderers/orderer.xxzx.com/tls/keystore/* ${PWD}/organizations/ordererOrganizations/xxzx.com/orderers/orderer.xxzx.com/tls/server.key

  mkdir -p ${PWD}/organizations/ordererOrganizations/xxzx.com/orderers/orderer.xxzx.com/msp/tlscacerts
  cp ${PWD}/organizations/ordererOrganizations/xxzx.com/orderers/orderer.xxzx.com/tls/tlscacerts/* ${PWD}/organizations/ordererOrganizations/xxzx.com/orderers/orderer.xxzx.com/msp/tlscacerts/tlsca.xxzx.com-cert.pem

  mkdir -p ${PWD}/organizations/ordererOrganizations/xxzx.com/msp/tlscacerts
  cp ${PWD}/organizations/ordererOrganizations/xxzx.com/orderers/orderer.xxzx.com/tls/tlscacerts/* ${PWD}/organizations/ordererOrganizations/xxzx.com/msp/tlscacerts/tlsca.xxzx.com-cert.pem

  infoln "Generating the admin msp"
  set -x
  fabric-ca-client enroll -u https://ordererAdmin:ordererAdminpw@localhost:9054 --caname ca-orderer -M ${PWD}/organizations/ordererOrganizations/xxzx.com/users/Admin@xxzx.com/msp --tls.certfiles ${PWD}/organizations/fabric-ca/ordererOrg/tls-cert.pem
  { set +x; } 2>/dev/null

  cp ${PWD}/organizations/ordererOrganizations/xxzx.com/msp/config.yaml ${PWD}/organizations/ordererOrganizations/xxzx.com/users/Admin@xxzx.com/msp/config.yaml

  set -x
  fabric-ca-client enroll -u https://orderer1:orderer1pw@localhost:9054 --caname ca-orderer -M ${PWD}/organizations/ordererOrganizations/xxzx.com/orderers/orderer1.xxzx.com/tls --enrollment.profile tls --csr.hosts orderer1.xxzx.com --csr.hosts localhost --tls.certfiles ${PWD}/organizations/fabric-ca/ordererOrg/tls-cert.pem
  { set +x; } 2>/dev/null

  cp ${PWD}/organizations/ordererOrganizations/xxzx.com/orderers/orderer1.xxzx.com/tls/tlscacerts/* ${PWD}/organizations/ordererOrganizations/xxzx.com/orderers/orderer1.xxzx.com/tls/ca.crt
  cp ${PWD}/organizations/ordererOrganizations/xxzx.com/orderers/orderer1.xxzx.com/tls/signcerts/* ${PWD}/organizations/ordererOrganizations/xxzx.com/orderers/orderer1.xxzx.com/tls/server.crt
  cp ${PWD}/organizations/ordererOrganizations/xxzx.com/orderers/orderer1.xxzx.com/tls/keystore/* ${PWD}/organizations/ordererOrganizations/xxzx.com/orderers/orderer1.xxzx.com/tls/server.key

  mkdir -p ${PWD}/organizations/ordererOrganizations/xxzx.com/orderers/orderer.xxzx.com/msp/tlscacerts
  cp ${PWD}/organizations/ordererOrganizations/xxzx.com/orderers/orderer1.xxzx.com/tls/tlscacerts/* ${PWD}/organizations/ordererOrganizations/xxzx.com/orderers/orderer1.xxzx.com/msp/tlscacerts/tlsca.xxzx.com-cert.pem

  mkdir -p ${PWD}/organizations/ordererOrganizations/xxzx.com/msp/tlscacerts
  cp ${PWD}/organizations/ordererOrganizations/xxzx.com/orderers/orderer1.xxzx.com/tls/tlscacerts/* ${PWD}/organizations/ordererOrganizations/xxzx.com/msp/tlscacerts/tlsca.xxzx.com-cert.pem

 set -x
  fabric-ca-client enroll -u https://orderer2:orderer2pw@localhost:9054 --caname ca-orderer -M ${PWD}/organizations/ordererOrganizations/xxzx.com/orderers/orderer2.xxzx.com/tls --enrollment.profile tls --csr.hosts orderer2.xxzx.com --csr.hosts localhost --tls.certfiles ${PWD}/organizations/fabric-ca/ordererOrg/tls-cert.pem
  { set +x; } 2>/dev/null

  cp ${PWD}/organizations/ordererOrganizations/xxzx.com/orderers/orderer2.xxzx.com/tls/tlscacerts/* ${PWD}/organizations/ordererOrganizations/xxzx.com/orderers/orderer2.xxzx.com/tls/ca.crt
  cp ${PWD}/organizations/ordererOrganizations/xxzx.com/orderers/orderer2.xxzx.com/tls/signcerts/* ${PWD}/organizations/ordererOrganizations/xxzx.com/orderers/orderer2.xxzx.com/tls/server.crt
  cp ${PWD}/organizations/ordererOrganizations/xxzx.com/orderers/orderer2.xxzx.com/tls/keystore/* ${PWD}/organizations/ordererOrganizations/xxzx.com/orderers/orderer2.xxzx.com/tls/server.key

  mkdir -p ${PWD}/organizations/ordererOrganizations/xxzx.com/orderers/orderer.xxzx.com/msp/tlscacerts
  cp ${PWD}/organizations/ordererOrganizations/xxzx.com/orderers/orderer2.xxzx.com/tls/tlscacerts/* ${PWD}/organizations/ordererOrganizations/xxzx.com/orderers/orderer2.xxzx.com/msp/tlscacerts/tlsca.xxzx.com-cert.pem

  mkdir -p ${PWD}/organizations/ordererOrganizations/xxzx.com/msp/tlscacerts
  cp ${PWD}/organizations/ordererOrganizations/xxzx.com/orderers/orderer2.xxzx.com/tls/tlscacerts/* ${PWD}/organizations/ordererOrganizations/xxzx.com/msp/tlscacerts/tlsca.xxzx.com-cert.pem
}
