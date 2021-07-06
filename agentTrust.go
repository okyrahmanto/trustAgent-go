/*
Copyright 2020 IBM All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"

	db "trustAgent-go/blockchain"

	mqtt "github.com/eclipse/paho.mqtt.golang"

	"github.com/gorilla/mux"

	"github.com/hyperledger/fabric-sdk-go/pkg/core/config"
	"github.com/hyperledger/fabric-sdk-go/pkg/gateway"
)

var wallet = os.DevNull
var ccPath = os.DevNull

var val = make(map[string]int)
var weight = make(map[string]int)

var ipOpenHAB = ""

var topicID = ""

var inboxMessage MessageAgent

var mainContract gateway.Contract

var ListConnectedDevice map[string]string

var clientMQTT mqtt.Client

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

type commandMQTT struct {
	Command string `json:"Command"`
	Content string `json:"Content"`
}

// function for rest
type MessageAgent struct {
	MessageID   string `json:"MessageID"`
	Source      string `json:"Source"`
	Destination string `json:"Destination"`
	Timestamp   string `json:"Timestamp"`
	Data        string `json:"Data"`
}

type Message struct {
	UID         string `json:"UID"`
	Topic       string `json:"Topic"`
	MessageType string `json:"MessageType"`
	Destination string `json:"Destination"`
	Source      string `json:"Source"`
	Sender      string `json:"Sender"`
	Content     string `json:"Content"`
}

type AgentIdentity struct {
	AgentID   string `json:"UID"`
	AgentName string `json:"UID"`
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
var agentIDentity AgentIdentity

func timeTrack(start time.Time, name string) {
	elapsed := time.Since(start)
	log.Printf("%s took %s", name, elapsed)
}

func homePage(w http.ResponseWriter, r *http.Request) {
	fmt.Fprintf(w, "Welcome to agent")
	fmt.Println("Endpoint Hit: homePage")
}

func messageReceiverAgent(w http.ResponseWriter, r *http.Request) { //whoever sent means data must be  fowrded to agent
	// get the body of our POST request
	// return the string response containing the request body
	//messages came from agent

	// get message
	reqBody, _ := ioutil.ReadAll(r.Body)
	//var contentJson map[string]interface{}
	var message MessageAgent
	json.Unmarshal([]byte(reqBody), &message)
	agentUrl := getAgentUrl(message.Destination)

	// send to device
	//SendMessageToDevice(agentUrl, message)

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	for {
		if inboxMessage.MessageID == "hei1" || ctx.Err() != nil {
			break
		}
	}

	//response := SendMessageToAgent(agentUrl, message)
	fmt.Println(message)
	// print message content
	fmt.Fprintf(w, "%+v", (agentUrl)) // response
	fmt.Fprintf(w, "%+v", ("<br>"))   // response
	fmt.Fprintf(w, "%+v", (message))  // response
	//fmt.Fprintf(w, "%+v", (message.Data))        // response

	//var dest concontentJson[]
	//fmt.Fprintf(w, "%+v", (response)) // response

	//fmt.Fprintf(w, "%+v", (message.Destination)) // response
	//fmt.Fprintf(w, "%+v", (message.Data))        // response
	//fmt.Fprintf(w, "%+v", string(reqBody)) // response
	//json.NewEncoder(w).Encode(messages)

}

func changeTopic(w http.ResponseWriter, r *http.Request) { //whoever sent means data must be  fowrded to agent
	// get the body of our POST request
	// return the string response containing the request body
	//messages came from agent

	topicID = "hei1"
	fmt.Fprintf(w, "%+v", ("changed to hei1")) // response

}

// get agent destination url
func getAgentUrl(device string) string {
	return "http://" + device + "-agent:10001/"
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

func SendMessageToDevice(device string, message Message) { // send to openHAB
	if ipOpenHAB == "" {
		ipOpenHAB = getHostOpenhab()
		//	ipOpenHAB = "192.168.56.109"
	}

	//ipOpenHAB = "192.168.56.109"
	println(ipOpenHAB)
	// curl -X PUT --header "Content-Type: text/plain" --header "Accept: application/json" -d "CLOSED" "http://{openHAB_IP}:8080/rest/items/My_Item/state"
	postBody, _ := json.Marshal(message)
	responseBody := bytes.NewBuffer(postBody)

	timeout := time.Duration(5 * time.Second)
	client := http.Client{
		Timeout: timeout,
	}

	header := map[string][]string{
		"Content-Type": {"text/plain"},
		"Accept":       {"application/json"},
	}
	//curl -X POST --header "Content-Type: text/plain" --header "Accept: application/json" -d "OFF" "http://{openHAB_IP}:8080/rest/items/My_Item"
	url := "http://" + ipOpenHAB + ":8080/rest/items/" + "device2" + "_command"
	println(url)
	req, err := http.NewRequest("POST", url, responseBody)
	req.Header = header

	if err != nil {
		log.Fatalln(err)
	}

	resp, err := client.Do(req)
	if err != nil {
		log.Fatalln(err)
	}

	defer resp.Body.Close()
	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		log.Fatalln(err)
	}
	log.Println(body)

}

func testCallDataFabric(w http.ResponseWriter, r *http.Request) {
	fmt.Fprintf(w, "Welcome to agent")
	fmt.Println("Endpoint Hit: out")
	getAllAgent(&mainContract)
}

func testInputDataToFabric(w http.ResponseWriter, r *http.Request) {
	fmt.Fprintf(w, "Welcome to agent")
	fmt.Println("Endpoint Hit: testin")
	putAgent(&mainContract)
}

func handleRequests() {
	myRouter := mux.NewRouter().StrictSlash(true)
	myRouter.HandleFunc("/", homePage)
	//myRouter.HandleFunc("/articles", returnAllArticles)
	// NOTE: Ordering is important here! This has to be defined before
	// the other `/article` endpoint.

	myRouter.HandleFunc("/agent", messageReceiverAgent).Methods("POST")
	myRouter.HandleFunc("/changetopic", changeTopic).Methods("POST")
	myRouter.HandleFunc("/device", messageReceiverDevice).Methods("POST")
	myRouter.HandleFunc("/testin", testInputDataToFabric).Methods("POST")
	myRouter.HandleFunc("/testout", testCallDataFabric).Methods("POST")

	//myRouter.HandleFunc("/article/{id}", returnSingleArticle)
	log.Fatal(http.ListenAndServe(":10000", myRouter))
}

func StartServer() {
	fmt.Println("Rest API v2.0 - Mux Routers")
	m := MessageData{createUID(), "Hello"}
	messageData, _ := json.Marshal(m)
	println(messageData)
	//test message output
	/*messages = []Message{
		{MessageID: createUID(), Source: "agent1", Destination: "agent2", Timestamp: createTimestamp(), Data: string(messageData)},
		{MessageID: createUID(), Source: "agent1", Destination: "agent3", Timestamp: createTimestamp(), Data: string(messageData)},
	}*/
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

func getHistoryTransaction(contract *gateway.Contract, deviceID string) map[string]string {
	getAllAgent(contract)
	m := make(map[string]string)
	return m
}

func calculateTrust(history map[string]string) float32 {
	time.Sleep(2)
	return 5
}

func decideTrust(trustValue float32) bool {
	if trustValue > 4 {
		return true
	}
	return false
}

func writeTransaction(contract *gateway.Contract) {
	putAgent(contract)
	time.Sleep(1)
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

func getAllAgent(contract *gateway.Contract) {
	log.Println("--> Evaluate Transaction: GetAllAgent, function returns all the current assets on the ledger")
	result, err := contract.EvaluateTransaction("GetAllAgent")
	if err != nil {
		log.Fatalf("Failed to evaluate transaction: %v", err)
	}
	log.Println(string(result))
}

func putAgent(contract *gateway.Contract) {
	log.Println("--> Submit Transaction: CreateAgent, creates new agent ")
	result, err := contract.SubmitTransaction("CreateAgent", createAgentID(createUID()), "device1", "device1/listen", "0", "50")
	if err != nil {
		log.Fatalf("Failed to Submit transaction: %v", err)
	}
	log.Println(string(result))
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
	return "127.0.0.1"
}

var logHandler mqtt.MessageHandler = func(client mqtt.Client, msg mqtt.Message) {
	//...
	log.Printf("Topic %s logged...\n", msg.Topic())
}

var registrationHandler mqtt.MessageHandler = func(client mqtt.Client, msg mqtt.Message) {
	//...
	log.Printf("Topic %s registered...\n", msg.Payload())
}

var agentSubscribeHandler mqtt.MessageHandler = func(client mqtt.Client, msg mqtt.Message) {
	//...
	//log.Printf("Topic %s registered...\n", msg.Topic())
	log.Printf("message received in topic %s ...\n", msg.Topic())

	//check topic for get deviceID
	deviceID := strings.Split(strings.Split(msg.Topic(), "-")[2], "/")[0]
	// get payload
	var rawPayload = string(msg.Payload())
	var message Message

	err := json.Unmarshal([]byte(rawPayload), &message)
	log.Printf("message received in topic %s ...\n", message)
	if err == nil {
		switch message.Sender {
		case "things":
			// send to agent

			// get history trustee
			history := getHistoryTransaction(&mainContract, message.Destination)
			// calculate trust
			trustValue := calculateTrust(history)
			// decide trust
			if decideTrust(trustValue) {
				// write transaction
				writeTransaction(&mainContract)
				// modify message
				println("sending to from things to agent")
				message.Sender = "agent"
				message.UID = createUID()
				messageForAgent, err := json.Marshal(message)
				if err != nil {
					fmt.Println(err)
					return
				}
				agentPublishHandler("agent-device-"+message.Destination+"/listen", string(messageForAgent))
			} else {
				log.Println("target cannot be trusted")
			}

		case "agent":
			// send to things (openhab)
			// modified messge
			println("sending to from representative agent to things")
			message.Sender = "things"
			message.UID = createUID()
			SendMessageToDevice(message.Destination, message)
		}
	} else {
		println(err)
	}

	println(deviceID)

}

func agentPublishHandler(topic string, content string) {
	clientMQTT.Publish(topic, 0, false, content)
}

var agentControllerHandler mqtt.MessageHandler = func(client mqtt.Client, msg mqtt.Message) {
	//...
	log.Printf("Topic %s logged...\n", msg.Topic())
	var rawPayload = string(msg.Payload())
	var cmd commandMQTT

	err := json.Unmarshal([]byte(rawPayload), &cmd)

	if err == nil {
		switch cmd.Command {
		case "device-add":
			addListConnectedDevice(cmd.Content)
			println("called add")
		case "device-remove":
			removeListConnectedDevice(cmd.Content)
			println("called remove")
		}
	}
	println(cmd.Command)
	//println(err)
	//showListConnectedDevice()

}

func showListConnectedDevice() {
	println(ListConnectedDevice)
	for k, v := range ListConnectedDevice {
		println("ID : " + k)
		println("Value : " + v)
	}
}

func addListConnectedDevice(deviceID string) {
	ListConnectedDevice[deviceID] = deviceID
	clientMQTT.Subscribe("agent-device-"+deviceID+"/listen", 0, agentSubscribeHandler)
	showListConnectedDevice()
}

func removeListConnectedDevice(deviceID string) {
	delete(ListConnectedDevice, deviceID)
	clientMQTT.Unsubscribe("agent-device-" + deviceID + "/listen")
	showListConnectedDevice()
}

func initializeMQTT() mqtt.Client {
	var opts = mqtt.NewClientOptions()
	opts.AddBroker(ipOpenHAB + ":1883")
	opts.SetClientID("go-controller")

	opts.SetDefaultPublishHandler(func(client mqtt.Client, msg mqtt.Message) {
		log.Printf("topic: %s\n", msg.Topic())
	})

	client := mqtt.NewClient(opts)
	if token := client.Connect(); token.Wait() && token.Error() != nil {
		log.Panicln(token.Error())
	}

	return client
}

func startMQTTClient() {
	keepAlive := make(chan os.Signal)
	signal.Notify(keepAlive, os.Interrupt, syscall.SIGTERM)
	clientMQTT = initializeMQTT()

	// subscribe to controller topic
	clientMQTT.Subscribe("agent-controller/command", 0, agentControllerHandler)

	<-keepAlive
}

func main() {
	// get env
	var agentIDentity AgentIdentity
	agentIDentity.AgentID = os.Getenv("agentID")
	agentIDentity.AgentName = os.Getenv("agentName")
	ListConnectedDevice = make(map[string]string)
	mainContract = db.InitApplication()
	ipOpenHAB = os.Args[2]
	//testTransaction(&contract)
	//SendMessageToDevice("device1")
	// run rest server
	//StartServer()
	//submitTransaction(contract)
	// using mqtt
	startMQTTClient()
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
