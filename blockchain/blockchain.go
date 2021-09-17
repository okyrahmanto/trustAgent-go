package blockchain

import (
	"fmt"
	"io/ioutil"
	"log"
	"os"
	"path/filepath"
	"strconv"
	"time"

	"github.com/google/uuid"
	"github.com/hyperledger/fabric-sdk-go/pkg/core/config"
	"github.com/hyperledger/fabric-sdk-go/pkg/gateway"
)

type Agent struct {
	AgentID      string `json:"AgentID"`
	DeviceID     string `json:"DeviceID"`
	SubcribePath string `json:"SubcribePath"`
	TrustValue   string `json:"TrustValue"`
	Tolerance    string `json:"Tolerance"`
}

func InitApplication() gateway.Contract {
	// init val and weight

	log.Println("remove wallet cache")
	err := os.RemoveAll("wallet")
	if err != nil {
		log.Fatal(err)
	}

	log.Println("============ application-golang starts ============")

	err = os.Setenv("DISCOVERY_AS_LOCALHOST", "true")
	if err != nil {
		log.Fatalf("Error setting DISCOVERY_AS_LOCALHOST environemnt variable: %v", err)
	}

	wallet, err := gateway.NewFileSystemWallet("wallet")
	if err != nil {
		log.Fatalf("Failed to create wallet: %v", err)
	}

	if !wallet.Exists("appUser") {
		err = populateWalletContent(wallet)
		if err != nil {
			log.Fatalf("Failed to populate wallet contents: %v", err)
		}
	}

	/*ccpPath := filepath.Join(
		//		"..",
		//		"..",
		"/Users/oky/Docker/fabric/fa2/new2/fabric-samples",
		"test-network",
		"organizations",
		"peerOrganizations",
		"org1.example.com",
		"connection-org1.yaml",
	)*/

	ccpPath := filepath.Join(
		"./config-fabric",
		"crypto-config",
		"peerOrganizations",
		"org1.example.com",
		"connection-org1.yaml",
	)

	gw, err := gateway.Connect(
		gateway.WithConfig(config.FromFile(filepath.Clean(ccpPath))),
		gateway.WithIdentity(wallet, "appUser"),
	)
	if err != nil {
		log.Fatalf("Failed to connect to gateway: %v", err)
	}
	defer gw.Close()

	network, err := gw.GetNetwork("mychannel")
	if err != nil {
		log.Fatalf("Failed to get network: %v", err)
	}

	contract := network.GetContract("trusted-chaincode")

	return *contract
}

func populateWalletContent(wallet *gateway.Wallet) error {
	log.Println("============ Populating wallet ============")
	/*credPath := filepath.Join(
		//		"..",
		//		"..",
		"/Users/oky/Docker/fabric/fa2/new2/fabric-samples",
		"test-network",
		"organizations",
		"peerOrganizations",
		"org1.example.com",
		"users",
		"Admin@org1.example.com",
		"msp",
	)*/

	credPath := filepath.Join(
		"./config-fabric",
		"crypto-config",
		"peerOrganizations",
		"org1.example.com",
		"users",
		"Admin@org1.example.com",
		"msp",
	)

	certPath := filepath.Join(credPath, "signcerts", "Admin@org1.example.com-cert.pem")
	// read the certificate pem
	cert, err := ioutil.ReadFile(filepath.Clean(certPath))
	if err != nil {
		return err
	}

	keyDir := filepath.Join(credPath, "keystore")
	// there's a single file in this dir containing the private key
	files, err := ioutil.ReadDir(keyDir)
	if err != nil {
		return err
	}
	if len(files) != 1 {
		return fmt.Errorf("keystore folder should have contain one file")
	}
	keyPath := filepath.Join(keyDir, files[0].Name())
	key, err := ioutil.ReadFile(filepath.Clean(keyPath))
	if err != nil {
		return err
	}

	identity := gateway.NewX509Identity("Org1MSP", string(cert), string(key))

	return wallet.Put("appUser", identity)
}

func CreateAgent(contract gateway.Contract, DeviceID string, TrustValue string, Tolerance string) string {
	log.Println("--> Submit Transaction: CreateAgent")
	AgentID := uuid.New()
	SubcribePath := "agent-device-" + DeviceID + "/listen"
	result, err := contract.SubmitTransaction("CreateAgent", AgentID.String(), DeviceID, SubcribePath, TrustValue, Tolerance)
	if err != nil {
		log.Fatalf("Failed to Submit transaction: %v", err)
	}
	log.Println(string(result))
	return AgentID.String()
}

func IsAgentExist(contract gateway.Contract, DeviceID string) bool {
	log.Println("--> Evaluate Transaction: Check Agent")
	result, err := contract.EvaluateTransaction("GetAgentByDevice", DeviceID)
	if err != nil {
		log.Fatalf("Failed to Submit transaction: %v", err)
	}
	//log.Println(string(result))
	return string(result) != "[]"
}

func GetAgentByDevice(contract gateway.Contract, DeviceID string) []byte {
	log.Println("--> Evaluate Transaction: Check Evaluate Agent")
	result, err := contract.EvaluateTransaction("GetAgentByDevice", DeviceID)
	if err != nil {
		log.Fatalf("Failed to Submit transaction: %v", err)
	}
	//println(string(result))
	return result
}

func GetHistoryEvaluation(contract *gateway.Contract, agentID string) []byte {
	log.Println("--> Evaluate Transaction: GetEvaluationByAgent")
	result, err := contract.EvaluateTransaction("GetEvaluationByAgent", agentID)
	if err != nil {
		log.Fatalf("Failed to Submit transaction: %v", err)
	}
	//println(string(result))
	return result
}

func CreateHistoryEvaluation(contract gateway.Contract, TransactionID string, AgentID string, AgentOwn string, AgentDestination string, ResponseTime string, Validity string, Correctness string, Cooperation string, Qos string, Availability string, Confidence string) string {
	log.Println("--> Submit Transaction: CreateEvaluation, ")
	evaluationID := uuid.New()
	timestamp := strconv.FormatInt(time.Now().UTC().UnixNano(), 10)
	fmt.Println("evaluation ID :" + evaluationID.String())
	fmt.Println("timestamp : " + timestamp)

	result, err := contract.SubmitTransaction("CreateEvaluationAgent", evaluationID.String(), TransactionID, AgentID, timestamp, AgentOwn, AgentDestination, ResponseTime, Validity, Correctness, Cooperation, Qos, Availability, Confidence)
	if err != nil {
		log.Fatalf("Failed to Submit transaction: %v", err)
	}
	log.Println(string(result))
	return string(result)
}
