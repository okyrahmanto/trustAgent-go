/*
Copyright 2020 IBM All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"time"

	"github.com/gorilla/mux"

	"github.com/hyperledger/fabric-sdk-go/pkg/core/config"
	"github.com/hyperledger/fabric-sdk-go/pkg/gateway"
)

var wallet = os.DevNull
var ccPath = os.DevNull

var val = make(map[string]int)
var weight = make(map[string]int)

var ipOpenHAB = ""

var mainContract gateway.Contract

//global func
func createTimestamp() string {
	return strconv.FormatInt(time.Now().Unix(), 10)
}

func createUID() string {
	//s := "sha1 this string"
	sha := sha256.New()
	sha.Write([]byte(createTimestamp()))
	sha1_hash := hex.EncodeToString(sha.Sum(nil))
	return sha1_hash[len(sha1_hash)-8:]
}

// function for rest
type Message struct {
	MessageID   string `json:"MessageID"`
	Source      string `json:"Source"`
	Destination string `json:"Destination"`
	Timestamp   string `json:"Timestamp"`
	Data        string `json:"Data"`
}

type MessageAgent struct {
	MessageType string `json:"MessageType"`
	Destination string `json:"Destination"`
	Data        string `json:"Data"`
}

/*
example data format for message Agent
{
	messageType : "",
	destination : "",
	data : ""
}


*/

type MessageData struct {
	requestType string `json:"requestType"`
	contents    string `json:"contents"`
}

var messages []Message

func homePage(w http.ResponseWriter, r *http.Request) {
	fmt.Fprintf(w, "Welcome to agent")
	fmt.Println("Endpoint Hit: homePage")
}

func messageReceiverAgent(w http.ResponseWriter, r *http.Request) { //whoever sent means data must be  fowrded to agent
	// get the body of our POST request
	// return the string response containing the request body
	//messages went this meat tobe send to agent

	reqBody, _ := ioutil.ReadAll(r.Body)
	//var contentJson map[string]interface{}
	var message MessageAgent
	json.Unmarshal([]byte(reqBody), &message)
	agentUrl := getAgentUrl(message.Destination)
	response := SendMessageToAgent(agentUrl, message)

	//var dest concontentJson[]
	fmt.Fprintf(w, "%+v", (response)) // response
	//println(message)
	//fmt.Fprintf(w, "%+v", (message.Destination)) // response
	//fmt.Fprintf(w, "%+v", (message.Data))        // response
	//fmt.Fprintf(w, "%+v", string(reqBody)) // response
	//json.NewEncoder(w).Encode(messages)
}

// get agent destination url
func getAgentUrl(device string) string {
	return "http://localhost:10001/device"
}

func messageReceiverDevice(w http.ResponseWriter, r *http.Request) { //whoever sent means data must be  fowrded to device
	// get the body of our POST request
	// return the string response containing the request body
	reqBody, _ := ioutil.ReadAll(r.Body)
	var contentJson map[string]interface{}
	json.Unmarshal([]byte(reqBody), &contentJson)

	fmt.Fprintf(w, "%+v", (contentJson["id"])) // response
	//fmt.Fprintf(w, "%+v", string(reqBody)) // response
	//json.NewEncoder(w).Encode(messages)
}

func SendMessageToAgent(agentURL string, message MessageAgent) MessageAgent { // send to agent
	postBody, _ := json.Marshal(message)
	responseBody := bytes.NewBuffer(postBody)
	//Leverage Go's HTTP Post function to make request
	resp, err := http.Post(agentURL, "application/json", responseBody)
	//Handle Error
	if err != nil {
		log.Fatalf("An Error Occured %v", err)
	}
	defer resp.Body.Close()
	//Read the response body
	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		log.Fatalln(err)
	}
	sb := string(body)
	var response MessageAgent
	json.Unmarshal(body, &response)
	log.Printf(sb)
	return response
}

func SendMessageToDevice(device string) { // send to openHAB
	if ipOpenHAB == "" {
		ipOpenHAB = getHostOpenhab()
	}
	// curl -X PUT --header "Content-Type: text/plain" --header "Accept: application/json" -d "CLOSED" "http://{openHAB_IP}:8080/rest/items/My_Item/state"
	postBody, _ := json.Marshal(map[string]string{
		"name":  "Toby",
		"email": "Toby@example.com",
	})
	responseBody := bytes.NewBuffer(postBody)
	//Leverage Go's HTTP Post function to make request
	resp, err := http.Post("http://"+ipOpenHAB+":8080/rest/items/"+device+"_command/state", "application/json", responseBody)
	//Handle Error
	if err != nil {
		log.Fatalf("An Error Occured %v", err)
	}
	defer resp.Body.Close()
	//Read the response body
	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		log.Fatalln(err)
	}
	sb := string(body)
	log.Printf(sb)
}

func handleRequests() {
	myRouter := mux.NewRouter().StrictSlash(true)
	myRouter.HandleFunc("/", homePage)
	//myRouter.HandleFunc("/articles", returnAllArticles)
	// NOTE: Ordering is important here! This has to be defined before
	// the other `/article` endpoint.
	myRouter.HandleFunc("/agent", messageReceiverAgent).Methods("POST")
	myRouter.HandleFunc("/device", messageReceiverDevice).Methods("POST")
	//myRouter.HandleFunc("/article/{id}", returnSingleArticle)
	log.Fatal(http.ListenAndServe(":10000", myRouter))
}

func StartServer() {
	fmt.Println("Rest API v2.0 - Mux Routers")
	m := MessageData{createUID(), "Hello"}
	messageData, _ := json.Marshal(m)
	//test message output
	messages = []Message{
		{MessageID: createUID(), Source: "agent1", Destination: "agent2", Timestamp: createTimestamp(), Data: string(messageData)},
		{MessageID: createUID(), Source: "agent1", Destination: "agent3", Timestamp: createTimestamp(), Data: string(messageData)},
	}
	handleRequests()
}

func initApplication() gateway.Contract {
	// init val and weight
	val["response_time"] = 10
	val["validity"] = 10
	val["correctness"] = 10
	val["cooperation"] = 10
	val["QoS"] = 10
	val["availability"] = 10
	val["confidence"] = 10

	weight["response_time"] = 10
	weight["validity"] = 10
	weight["correctness"] = 10
	weight["cooperation"] = 10
	weight["QoS"] = 10
	weight["availability"] = 10
	weight["confidence"] = 10

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
		//		"..",
		//		"..",
		"/Users/oky/Docker/fabric/fa2/new2/fabric-samples",
		"4host-swarm",
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

	contract := network.GetContract("fabcar")

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
		//		"..",
		//		"..",
		"/Users/oky/Docker/fabric/fa2/new2/fabric-samples",
		"4host-swarm",
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

func submitTransaction(contract gateway.Contract) {
	log.Println("--> Submit Transaction: InitLedger, function creates the initial set of assets on the ledger")
	result, err := contract.SubmitTransaction("InitLedgerMod")
	if err != nil {
		log.Fatalf("Failed to Submit transaction: %v", err)
	}
	log.Println(string(result))
}

func evaluateTransaction(contract gateway.Contract) {
	log.Println("--> Submit Transaction: InitLedger, function creates the initial set of assets on the ledger")
	result, err := contract.EvaluateTransaction("GetAllAssets")
	if err != nil {
		log.Fatalf("Failed to evaluate transaction: %v", err)
	}
	log.Println(string(result))
}

func addTransaction(contract gateway.Contract, agentID string) {

}

func addAgent(contract gateway.Contract) {

}

func createAgentID(deviceID string) (agentID string) {
	//s := "sha1 this string"
	sha := sha256.New()
	sha.Write([]byte(deviceID))
	sha1_hash := hex.EncodeToString(sha.Sum(nil))
	return sha1_hash[len(sha1_hash)-8:]
}

func wRating(val map[string]int, weight map[string]int) float32 {
	//var m map[string]int;
	//n := len(val)
	sumWR := 0
	sumW := 0
	for key, value := range val {
		fmt.Println("Key:", key, "Value:", value)
		sumWR += weight[key] * value
	}

	for key, value := range weight {
		fmt.Println("Key:", key, "Value:", value)
		sumW += value
	}
	return float32(sumWR) / float32(sumW)
}

func testTransaction(contract *gateway.Contract) {

	log.Println("--> Evaluate Transaction: GetAllAgent, function returns all the current assets on the ledger")
	result, err := contract.EvaluateTransaction("GetAllAgent")
	if err != nil {
		log.Fatalf("Failed to evaluate transaction: %v", err)
	}
	log.Println(string(result))

	log.Println("--> Submit Transaction: CreateAgent, creates new agent ")
	result, err = contract.SubmitTransaction("CreateAgent", createAgentID("device1"), "device1", "device2/listen", "0", "50")
	if err != nil {
		log.Fatalf("Failed to Submit transaction: %v", err)
	}
	log.Println(string(result))

	log.Println("--> Evaluate Transaction: GetAgent, function returns an asset with a given assetID")
	result, err = contract.EvaluateTransaction("GetAgent", "e0ef4a44")
	if err != nil {
		log.Fatalf("Failed to evaluate transaction: %v\n", err)
	}
	log.Println(string(result))

	log.Println("--> Submit Transaction: AddtransactionAgent, add transaction agent ")
	result, err = contract.SubmitTransaction("AddTransactionAgent", "e0ef4a44", "e0ef4a44", "c259ec20", "request", "", createTimestamp())
	if err != nil {
		log.Fatalf("Failed to Submit transaction: %v", err)
	}
	log.Println(string(result))

	log.Println("--> Evaluate Transaction: GetAgent, function returns an asset with a given assetID")
	result, err = contract.EvaluateTransaction("GetAgent", "e0ef4a44")
	if err != nil {
		log.Fatalf("Failed to evaluate transaction: %v\n", err)
	}
	log.Println(string(result))
}

func getHostOpenhab() string {
	//output, err := exec.Command("/bin/bash", "-c", "/sbin/ip route | awk '/default/ { print $3 }'").Output()
	//if err != nil {
	//	log.Fatal(err)
	//}
	return "openhab"
}

func main() {

	//mainContract = initApplication()

	//testTransaction(&contract)
	//SendMessageToDevice("device1")
	// run rest server
	StartServer()
	//submitTransaction(contract)
	/*

		log.Println("--> Evaluate Transaction: GetAllAgent, function returns all the current assets on the ledger")
		result, err = contract.EvaluateTransaction("GetAllAgent")
		if err != nil {
			log.Fatalf("Failed to evaluate transaction: %v", err)
		}
		log.Println(string(result))
	*/
	/*log.Println("--> Submit Transaction: InitLedger, function creates the initial set of assets on the ledger")
	result, err := contract.SubmitTransaction("InitLedger")
	if err != nil {
		log.Fatalf("Failed to Submit transaction: %v", err)
	}
	log.Println(string(result))

	log.Println("--> Evaluate Transaction: GetAsset, function returns an asset with a given assetID")
	result, err = contract.EvaluateTransaction("GetAgent", "device1")
	if err != nil {
		log.Fatalf("Failed to evaluate transaction: %v\n", err)
	}
	log.Println(string(result))


	log.Println("--> Evaluate Transaction: GetAllAssets, function returns all the current assets on the ledger")
	result, err := contract.EvaluateTransaction("GetAllAssets")
	if err != nil {
		log.Fatalf("Failed to evaluate transaction: %v", err)
	}
	log.Println(string(result))

	log.Println("--> Submit Transaction: CreateAsset, creates new asset with ID, color, owner, size, and appraisedValue arguments")
	result, err = contract.SubmitTransaction("CreateAsset", "asset15", "yellow", "5", "Tom", "1300")
	if err != nil {
		log.Fatalf("Failed to Submit transaction: %v", err)
	}
	log.Println(string(result))

	log.Println("--> Evaluate Transaction: ReadAsset, function returns an asset with a given assetID")
	result, err = contract.EvaluateTransaction("ReadAssetMod", "asset1")
	if err != nil {
		log.Fatalf("Failed to evaluate transaction: %v\n", err)
	}
	log.Println(string(result))

	log.Println("--> Evaluate Transaction: AssetExists, function returns 'true' if an asset with given assetID exist")
	result, err = contract.EvaluateTransaction("AssetExists", "asset1")
	if err != nil {
		log.Fatalf("Failed to evaluate transaction: %v\n", err)
	}
	log.Println(string(result))
	*/
	/*log.Println("--> Submit Transaction: TransferAsset asset1, transfer to new owner of Tom")
	_, err = contract.SubmitTransaction("TransferAsset", "asset1", "Tom")
	if err != nil {
		log.Fatalf("Failed to Submit transaction: %v", err)
	}

	log.Println("--> Evaluate Transaction: ReadAsset, function returns 'asset1' attributes")
	result, err = contract.EvaluateTransaction("ReadAsset", "asset1")
	if err != nil {
		log.Fatalf("Failed to evaluate transaction: %v", err)
	}
	log.Println(string(result))
	*/
	log.Println("============ application-golang ends ============")
}
