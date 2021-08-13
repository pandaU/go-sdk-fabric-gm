package enroll

import (
	"fmt"
	mspca "github.com/hyperledger/fabric-sdk-go/pkg/client/msp"
	configca "github.com/hyperledger/fabric-sdk-go/pkg/core/config"
	fabsdkca "github.com/hyperledger/fabric-sdk-go/pkg/fabsdk"
	"os"
)

func Main() {
	c := configca.FromFile("C:\\Users\\MSI\\go\\src\\github.com\\hyperledger\\go-sdk-gm\\main\\config_test.yaml")
	sdk, err := fabsdkca.New(c)
	if err != nil {
		fmt.Printf("Failed to create new SDK: %s\n", err)
		os.Exit(1)
	}
	defer sdk.Close()
	enrollUserCa(sdk, "admin", "adminpw")
}

func enrollUserCa(sdk *fabsdkca.FabricSDK, user string, secret string) {
	ctx := sdk.Context()
	mspClient, err := mspca.New(ctx)
	if err != nil {
		fmt.Printf("Failed to create msp client: %s\n", err)
	}

	fmt.Println("Going to enroll user")
	err = mspClient.Enroll(user, mspca.WithSecret(secret))

	if err != nil {
		fmt.Printf("Failed to enroll user: %s\n", err)
	} else {
		fmt.Printf("Success enroll user: %s\n", user)
	}

}

func registerUserCa(user string, secret string, sdk *fabsdkca.FabricSDK) {

	ctxProvider := sdk.Context()

	// Get the Client.
	// Without WithOrg option, it uses default client organization.
	msp1, err := mspca.New(ctxProvider)
	if err != nil {
		fmt.Printf("failed to create CA client: %s", err)
	}

	request := &mspca.RegistrationRequest{Name: user, Secret: secret, Type: "client", Affiliation: "org1.department1"}
	_, err = msp1.Register(request)
	if err != nil {
		fmt.Printf("Register return error %s", err)
	}

}
