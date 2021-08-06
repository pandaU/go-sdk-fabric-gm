module github.com/VoneChain-CS/fabric-sdk-go-gm

go 1.14

require (
	github.com/Knetic/govaluate v3.0.0+incompatible
	github.com/VividCortex/gohistogram v1.0.0 // indirect
	github.com/VoneChain-CS/fabric-sdk-go-gm/cfssl v0.0.0-20201021101014-9a2abd087e1c
	github.com/cloudflare/cfssl v1.4.1
	github.com/go-kit/kit v0.9.0
	github.com/golang/mock v1.4.4
	github.com/golang/protobuf v1.4.2
	github.com/grantae/certinfo v0.0.0-20170412194111-59d56a35515b
	github.com/hyperledger/fabric-config v0.0.5
	github.com/hyperledger/fabric-lib-go v1.0.0
	github.com/hyperledger/fabric-protos-go v0.0.0-20200707132912-fee30f3ccd23
	github.com/miekg/pkcs11 v1.0.3
	github.com/mitchellh/mapstructure v1.3.3
	github.com/pkg/errors v0.8.1
	github.com/prometheus/client_golang v1.7.1
	github.com/spf13/cast v1.3.1
	github.com/spf13/viper v1.7.1
	github.com/stretchr/testify v1.6.1
	github.com/tjfoc/gmsm v1.3.2
	github.com/tjfoc/gmtls v1.2.1
	go.etcd.io/etcd v3.3.13+incompatible // indirect
	golang.org/x/crypto v0.0.0-20201016220609-9e8e0b390897
	golang.org/x/net v0.0.0-20200625001655-4c5254603344
	google.golang.org/grpc v1.29.1
	gopkg.in/yaml.v2 v2.3.0
)

replace (
	github.com/VoneChain-CS/fabric-sdk-go-gm/cfssl v0.0.0-20201021101014-9a2abd087e1c => ./cfssl
	github.com/spf13/cast v1.3.1 => ./spf13/cast
	github.com/spf13/cobra => ./spf13/cobra
	github.com/spf13/jwalterweatherman => ./spf13/jwalterweatherman
	github.com/spf13/pflag => ./spf13/pflag
	github.com/tjfoc/gmsm v1.3.2 => ./tjfoc/gmsm
	github.com/tjfoc/gmtls v1.2.1 => ./tjfoc/gmtls
)
