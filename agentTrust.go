/*
Copyright 2020 IBM All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package main

import (
	"bytes"
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"math/big"
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
	"github.com/mitchellh/mapstructure"
)

var wallet = os.DevNull
var ccPath = os.DevNull

var val = make(map[string]int)
var weight = make(map[string]float64)

var ipOpenHAB = ""

var topicID = ""

var inboxMessage MessageAgent

var mainContract gateway.Contract

var ListConnectedDevice map[string]Agent //active agent list

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
	RefUID      string `json:"RefUID"`
	Topic       string `json:"Topic"`
	MessageType string `json:"MessageType"`
	Destination string `json:"Destination"`
	Source      string `json:"Source"`
	Sender      string `json:"Sender"`
	Content     string `json:"Content"`
	Pubx        string `json:"Pubx"`
	Puby        string `json:"Puby"`
}

type AgentIdentity struct {
	AgentID   string `json:"UID"`
	AgentName string `json:"UID"`
}

type Agent struct {
	AgentID      string `json:"AgentID"`
	DeviceID     string `json:"DeviceID"`
	SubcribePath string `json:"SubcribePath"`
	TrustValue   string `json:"TrustValue"`
	Tolerance    string `json:"Tolerance"`
}

type QueryResultAgent struct {
	Key    string `json:"Key"`
	Record *Agent
}

type EvaluationParam struct {
	EvaluationID  string `json:"EvaluationID"` //uuid
	TransactionID string `json:"TransactionID"`
	AgentID       string `json:"AgentID"`
	Timestamp     string `json:"Timestamp"`
	ResponseTime  string `json:"ResponseTime"`
	Validity      string `json:"Validity"`
	Correctness   string `json:"Correctness"`
	Cooperation   string `json:"Cooperation"`
	Qos           string `json:"Qos"`
	Availability  string `json:"Availability"`
	Confidence    string `json:"Confidence"`
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

var priv ecdsa.PrivateKey
var pubk ecdsa.PublicKey

var pubkOpposite ecdsa.PublicKey

var sharedKey [32]byte

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

func getHistoryTransaction(contract *gateway.Contract, agentID string) []EvaluationParam {
	listEvaluationParamAsBytes := db.GetHistoryEvaluation(contract, agentID)

	var listEvaluationParamRaw []map[string]interface{}

	//var listAgent []Agent
	json.Unmarshal(listEvaluationParamAsBytes, &listEvaluationParamRaw)
	//listAgent = listAgentRaw[0]
	resultListEvaluationParam := []EvaluationParam{}

	//fmt.Println(listEvaluationParamRaw)
	for _, v := range listEvaluationParamRaw {
		var evaluationParam EvaluationParam
		mapstructure.Decode(v["Record"], &evaluationParam)
		resultListEvaluationParam = append(resultListEvaluationParam, evaluationParam)

	}
	fmt.Println(resultListEvaluationParam)
	//mapstructure.Decode(listAgentRaw[0]["Record"], &agentDestination)
	return resultListEvaluationParam
}

func calculateTrust(agentDestination Agent, history []EvaluationParam) float64 {

	weight["response_time"] = 7.0
	weight["validity"] = 7.0
	weight["correctness"] = 7.0
	weight["cooperation"] = 7.0
	weight["QoS"] = 7.0
	weight["availability"] = 10.0
	weight["confidence"] = 7.0

	var evaluationNumber int
	sumAllRating := 0.0
	if len(history) > 1 {
		for k, v := range history {
			response_time, _ := strconv.ParseFloat(v.ResponseTime, 32)
			validity, _ := strconv.ParseFloat(v.Validity, 32)
			coop, _ := strconv.ParseFloat(v.Cooperation, 32)
			qos, _ := strconv.ParseFloat(v.Qos, 32)
			correctness, _ := strconv.ParseFloat(v.Correctness, 32)
			confidence, _ := strconv.ParseFloat(v.Confidence, 32)
			availability, _ := strconv.ParseFloat(v.Availability, 32)

			sumWeightedRatingEvaluation := response_time*weight["response_time"] + validity*weight["validity"] + coop*weight["cooperation"] + qos*weight["qos"] + correctness*weight["correctness"] + confidence*weight["confidence"] + availability*weight["availability"]
			sumWeight := weight["response_time"] + weight["validity"] + weight["correctness"] + weight["cooperation"] + weight["QoS"] + weight["availability"] + weight["confidence"]

			sumAllRating = sumAllRating + (sumWeightedRatingEvaluation / sumWeight)
			evaluationNumber = k
		}
		evaluationNumber++
		return sumAllRating / float64(evaluationNumber)
	} else {
		return 5 // default if no trx
	}

}

func decideTrust(agent Agent, resultCalculation float64) bool {
	agentTrust, _ := strconv.ParseFloat(agent.TrustValue, 32)
	fmt.Print("agent Trust : ")
	fmt.Println(agentTrust)
	fmt.Print("result Calculation : ")
	fmt.Println(resultCalculation)

	/*if resultCalculation > agentTrust {
		return true
	}
	return false*/
	return resultCalculation > agentTrust
}

func writeTransaction(contract *gateway.Contract, agentOwn Agent, agentDestination Agent, ResponseTime string, Validity string, Correctness string, Cooperation string, Qos string, Availability string, Confidence string) {

	db.CreateHistoryEvaluation(*contract, "trx01", agentOwn.AgentID, agentOwn.AgentID, agentDestination.AgentID, ResponseTime, Validity, Correctness, Cooperation, Qos, Availability, Confidence)

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

func encryptMessage(message []byte) []byte {

	//conv to slice
	sliceSharedKey := sharedKey[:]
	key := []byte(sliceSharedKey)
	//key := []byte("passphrasewhichneedstobe32bytes!")
	text := message

	// generate a new aes cipher using our 32 byte long key
	c, err := aes.NewCipher(key)
	// if there are any errors, handle them
	if err != nil {
		fmt.Println(err)
	}

	// gcm or Galois/Counter Mode, is a mode of operation
	// for symmetric key cryptographic block ciphers
	// - https://en.wikipedia.org/wiki/Galois/Counter_Mode
	gcm, err := cipher.NewGCM(c)
	// if any error generating new GCM
	// handle them
	if err != nil {
		fmt.Println(err)
	}

	// creates a new byte array the size of the nonce
	// which must be passed to Seal
	nonce := make([]byte, gcm.NonceSize())
	// populates our nonce with a cryptographically secure
	// random sequence
	if _, err = io.ReadFull(rand.Reader, nonce); err != nil {
		fmt.Println(err)
	}

	// here we encrypt our text using the Seal function
	// Seal encrypts and authenticates plaintext, authenticates the
	// additional data and appends the result to dst, returning the updated
	// slice. The nonce must be NonceSize() bytes long and unique for all
	// time, for a given key.
	//fmt.Println(gcm.Seal(nonce, nonce, text, nil))
	return gcm.Seal(nonce, nonce, text, nil)
}

func decryptMessage(message []byte) []byte {

	//conv to slice
	sliceSharedKey := sharedKey[:]
	key := []byte(sliceSharedKey)
	//key := []byte("passphrasewhichneedstobe32bytes!")
	//ciphertext := []byte(message)

	//conv to slice
	ciphertext := message

	// if our program was unable to read the file
	// print out the reason why it can't
	//if err != nil {
	//    fmt.Println(err)
	//}

	c, err := aes.NewCipher(key)
	if err != nil {
		fmt.Println(err)
	}

	gcm, err := cipher.NewGCM(c)
	if err != nil {
		fmt.Println(err)
	}

	nonceSize := gcm.NonceSize()
	if len(ciphertext) < nonceSize {
		fmt.Println(err)
	}

	nonce, ciphertext := ciphertext[:nonceSize], ciphertext[nonceSize:]
	plaintext, err := gcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		fmt.Println(err)
	}
	//fmt.Println(string(plaintext))
	return plaintext
}

func generateKey() (ecdsa.PrivateKey, ecdsa.PublicKey) {
	priv, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	pub := priv.PublicKey
	return *priv, pub
}

func combineKey(priv ecdsa.PrivateKey, pubv ecdsa.PublicKey, pubx string, puby string) [32]byte {
	pubax := new(big.Int)
	pubax.SetString(pubx, 10)

	pubay := new(big.Int)
	pubay.SetString(puby, 10)

	p, _ := pubv.Curve.ScalarMult(pubax, pubay, priv.D.Bytes())
	keyResult := sha256.Sum256(p.Bytes())
	//fmt.Printf("\nShared key   %x\n", keyResult)
	return keyResult
}

func thingsHandler(message Message, topic string) {
	//check topic for get deviceID
	deviceID := strings.Split(strings.Split(topic, "-")[2], "/")[0]
	agentOwn := ListConnectedDevice[deviceID]
	historyEvaluation := getHistoryTransaction(&mainContract, message.Destination)
	// calculate trust
	trustValue := calculateTrust(agentOwn, historyEvaluation)
	// decide trust
	if decideTrust(agentOwn, trustValue) {
		message.MessageType = "evaluateReq"
		message.Sender = "agent"
		message.Pubx = pubk.X.String()
		message.Puby = pubk.Y.String()
		messageForAgent, err := json.Marshal(message)
		if err != nil {
			fmt.Println(err)
			return
		}
		agentPublishHandler("agent/agent-device-"+message.Destination+"/listen", string(messageForAgent))
	} else {
		agentDestination := getAgentByID(message.Destination)
		writeTransaction(&mainContract, agentOwn, agentDestination, "4", "4", "4", "4", "4", "4", "4")
	}
}

func agentHandler(message Message, topic string) {
	deviceID := strings.Split(strings.Split(topic, "-")[2], "/")[0]
	agentOwn := ListConnectedDevice[deviceID]

	if message.MessageType == "evaluateReq" {
		historyEvaluation := getHistoryTransaction(&mainContract, message.Source)
		// calculate trust
		trustValue := calculateTrust(agentOwn, historyEvaluation)
		if decideTrust(agentOwn, trustValue) {
			pubax := new(big.Int)
			pubax.SetString(message.Pubx, 10)

			pubay := new(big.Int)
			pubay.SetString(message.Puby, 10)
			pubkOpposite.X = pubax
			pubkOpposite.X = pubay
			sharedKey = combineKey(priv, pubk, message.Pubx, message.Puby)

			message.MessageType = "evaluateReply"
			message.Sender = "agent"
			message.Pubx = pubk.X.String()
			message.Puby = pubk.Y.String()

			messageForAgent, err := json.Marshal(message)
			if err != nil {
				fmt.Println(err)
				return
			}
			agentPublishHandler("agent/agent-device-"+message.Source+"/listen", string(messageForAgent))

		}
	} else if message.MessageType == "evaluateReply" {
		pubax := new(big.Int)
		pubax.SetString(message.Pubx, 10)

		pubay := new(big.Int)
		pubay.SetString(message.Puby, 10)
		pubkOpposite.X = pubax
		pubkOpposite.X = pubay
		sharedKey = combineKey(priv, pubk, message.Pubx, message.Puby)

		// encrypt
		message.MessageType = "dataReq"
		messageForAgent, err := json.Marshal(message)
		if err != nil {
			fmt.Println(err)
			return
		}
		//encryptedMessage := string(encryptMessage(string(messageForAgent)))
		fmt.Print("before : ")
		fmt.Println(messageForAgent)
		encryptedMessage := encryptMessage(messageForAgent)
		fmt.Print("hasil raw encode")
		fmt.Println(encryptedMessage)
		fmt.Print("after : ")
		fmt.Println(decryptMessage(encryptedMessage))

		//send encrypted
		agentPublishHandler("agent/agent-device-"+message.Destination+"/secure", string(encryptedMessage))
	} else if message.MessageType == "dataReq" {
		//time.Sleep(10000) // wait respon from things
		// encrypt
		message.MessageType = "dataReply"
		messageForAgent, err := json.Marshal(message)
		if err != nil {
			fmt.Println(err)
			return
		}
		//encryptedMessage := string(encryptMessage(string(messageForAgent)))
		encryptedMessage := encryptMessage(messageForAgent)
		agentPublishHandler("agent/agent-device-"+message.Source+"/secure", string(encryptedMessage))

		agentDestination := getAgentByID(message.Source)
		writeTransaction(&mainContract, agentOwn, agentDestination, "9", "9", "9", "9", "9", "9", "9")
	} else if message.MessageType == "dataReply" {
		//time.Sleep(10000)
		// encrypt
		//evaluate(message)
		//write evaluation
		agentDestination := getAgentByID(message.Destination)
		writeTransaction(&mainContract, agentOwn, agentDestination, "9", "9", "9", "9", "9", "9", "9")

	}
}

func getAgentByID(deviceID string) Agent {
	var agentDestination Agent

	// check if device already registered in own hub
	if isAlreadyInListConnected(deviceID) {
		agentDestination = ListConnectedDevice[deviceID]
	} else {
		// check in ledger
		if db.IsAgentExist(mainContract, deviceID) {
			listAgentAsBytes := db.GetAgentByDevice(mainContract, deviceID)
			var listAgentRaw []map[string]interface{}

			//var listAgent []Agent
			_ = json.Unmarshal(listAgentAsBytes, &listAgentRaw)
			//listAgent = listAgentRaw[0]

			fmt.Println(listAgentRaw[0]["Record"])

			mapstructure.Decode(listAgentRaw[0]["Record"], &agentDestination)
		} else {
			fmt.Println("agent not registered yet")
		}
	}

	return agentDestination

}

var agentSubscribeHandler mqtt.MessageHandler = func(client mqtt.Client, msg mqtt.Message) {
	//...
	//log.Printf("Topic %s registered...\n", msg.Topic())
	log.Printf("message received in topic %s ...\n", msg.Topic())

	// try to encrypt the message

	//check topic for get deviceID
	//deviceID := strings.Split(strings.Split(msg.Topic(), "-")[2], "/")[0]
	//agentOwn := ListConnectedDevice[deviceID]
	// get payload
	var rawPayload = string(msg.Payload())
	var message Message

	fmt.Println("payload awal raw : ")
	fmt.Println(msg.Payload())
	if strings.Split(msg.Topic(), "/")[2] == "secure" { // listen secure
		decrypted := decryptMessage(msg.Payload())
		fmt.Println("hasil decrypt : ")
		fmt.Println(decrypted)
		err := json.Unmarshal([]byte(decrypted), &message)
		var agentDestination Agent
		fmt.Println("hasil pesan : ")
		fmt.Println(message)
		// check if device already registered in own hub
		if isAlreadyInListConnected(message.Destination) {
			agentDestination = ListConnectedDevice[message.Destination]
		} else {
			// check in ledger
			if db.IsAgentExist(mainContract, message.Destination) {
				listAgentAsBytes := db.GetAgentByDevice(mainContract, message.Destination)
				var listAgentRaw []map[string]interface{}

				//var listAgent []Agent
				_ = json.Unmarshal(listAgentAsBytes, &listAgentRaw)
				//listAgent = listAgentRaw[0]

				fmt.Println(listAgentRaw[0]["Record"])

				mapstructure.Decode(listAgentRaw[0]["Record"], &agentDestination)
			} else {
				fmt.Println("agent not registered yet")
			}
		}

		if err == nil {
			switch message.Sender {
			case "things":
				thingsHandler(message, msg.Topic())
			case "agent":
				agentHandler(message, msg.Topic())
			}
		}

	} else { //listen normal
		err := json.Unmarshal([]byte(rawPayload), &message)
		var agentDestination Agent
		// check if device already registered in own hub
		if isAlreadyInListConnected(message.Destination) {
			agentDestination = ListConnectedDevice[message.Destination]
		} else {
			// check in ledger
			if db.IsAgentExist(mainContract, message.Destination) {
				listAgentAsBytes := db.GetAgentByDevice(mainContract, message.Destination)
				var listAgentRaw []map[string]interface{}

				//var listAgent []Agent
				_ = json.Unmarshal(listAgentAsBytes, &listAgentRaw)
				//listAgent = listAgentRaw[0]

				fmt.Println(listAgentRaw[0]["Record"])

				mapstructure.Decode(listAgentRaw[0]["Record"], &agentDestination)
			} else {
				fmt.Println("agent not registered yet")
			}
		}

		log.Printf("message received in topic %s ...\n", message)
		if err == nil {
			switch message.Sender {
			case "things":
				thingsHandler(message, msg.Topic())
				// send to agent
				/*
					// get history trustee
					historyEvaluation := getHistoryTransaction(&mainContract, message.Destination)

					// calculate trust
					trustValue := calculateTrust(agentOwn, historyEvaluation)
					// decide trust
					if decideTrust(agentOwn, trustValue) {
						// write transaction
						//writeTransaction(&mainContract)
						// modify message
						println("sending to from things to agent")
						message.Sender = "agent"
						message.UID = createUID()
						messageForAgent, err := json.Marshal(message)
						if err != nil {
							fmt.Println(err)
							return
						}
						agentPublishHandler("agent/agent-device-"+message.Destination+"/listen", string(messageForAgent))
						//writeTransaction(&mainContract, agentOwn, agentDestination, "9", "9", "9", "9", "9", "9", "9")
					} else {
						log.Println("target cannot be trusted")
						// write history transaction
						writeTransaction(&mainContract, agentOwn, agentDestination, "3", "3", "3", "3", "3", "3", "3")
						// write evaluation
					}
				*/
			case "agent":
				agentHandler(message, msg.Topic())
				// send to things (openhab)
				// modified messge
				/* ////////
				// get history trustee
				historyEvaluation := getHistoryTransaction(&mainContract, message.Source)

				// calculate trust
				trustValue := calculateTrust(agentOwn, historyEvaluation)
				if !decideTrust(agentOwn, trustValue) {
					/*
						// sebaiknya di hold untuk menunggu balasan dari perangkat
						println("sending to from things to agent")

						message.Sender = "things"
						message.RefUID = message.UID
						message.UID = createUID()
						message.Content = "{\"status\":\"unavailable\"}"
						messageForAgent, err := json.Marshal(message)
						if err != nil {
							fmt.Println(err)
							return
						}
						agentPublishHandler("agent/agent-device-"+message.Destination+"/listen", string(messageForAgent))
						//writeTransaction(&mainContract, agentOwn, agentDestination, "9", "9", "9", "9", "9", "9", "9")
				*/
				/*
					} else {
						log.Println("target cannot be trusted")

						println("sending to from things to agent")
						message.Sender = ""
						message.RefUID = message.UID
						message.UID = createUID()
						message.Content = ""
						messageForAgent, err := json.Marshal(message)
						if err != nil {
							fmt.Println(err)
							return
						}
						agentPublishHandler("agent/agent-device-"+message.Source+"/listen", string(messageForAgent))
						// write history transaction
						writeTransaction(&mainContract, agentOwn, agentDestination, "3", "3", "3", "3", "3", "3", "3")
						// write evaluation
					}

					println("sending to from representative agent to things")
					message.Sender = "things"
					message.UID = createUID()
					SendMessageToDevice(message.Destination, message)
				*/
			}

		} else {
			println(err)
		}
	}

	//println(deviceID)

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
			// check if already exist in listconnected
			if !isAlreadyInListConnected(cmd.Content) {
				// check if already exist in ledger
				if !db.IsAgentExist(mainContract, cmd.Content) {
					// create new agent in ledger
					AgentID := db.CreateAgent(mainContract, cmd.Content, "4", "1")
					agent := Agent{AgentID: AgentID, SubcribePath: "agent/agent-device-" + cmd.Content + "/listen", DeviceID: cmd.Content, TrustValue: "4", Tolerance: "1"}
					addListConnectedDevice(cmd.Content, agent)
					println("device-add : new agent")
				} else {
					// get agent details
					listAgentAsBytes := db.GetAgentByDevice(mainContract, cmd.Content)
					var listAgentRaw []map[string]interface{}

					//var listAgent []Agent
					_ = json.Unmarshal(listAgentAsBytes, &listAgentRaw)
					//listAgent = listAgentRaw[0]

					fmt.Println(listAgentRaw[0]["Record"])
					var agent Agent
					mapstructure.Decode(listAgentRaw[0]["Record"], &agent)
					fmt.Println(agent)
					//agent := listAgentRaw[0]["Record"]
					//json.Unmarshal([]byte(agent), &listAgentRaw)
					addListConnectedDevice(cmd.Content, agent)
					println("device-add : old agent")
				}
				println("called add")
			} else {
				println("already connected")
			}
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
		print("Value : ")
		fmt.Println(v)
	}
}

func isAlreadyInListConnected(deviceID string) bool {
	for k, _ := range ListConnectedDevice {
		if k == deviceID {
			return true
		}
	}
	return false
}

func addListConnectedDevice(deviceID string, agent Agent) {
	ListConnectedDevice[deviceID] = agent
	clientMQTT.Subscribe("agent/agent-device-"+deviceID+"/listen", 0, agentSubscribeHandler)
	clientMQTT.Subscribe("agent/agent-device-"+deviceID+"/secure", 0, agentSubscribeHandler)
	showListConnectedDevice()
}

func removeListConnectedDevice(deviceID string) {
	delete(ListConnectedDevice, deviceID)
	clientMQTT.Unsubscribe("agent/agent-device-" + deviceID + "/listen")
	clientMQTT.Unsubscribe("agent/agent-device-" + deviceID + "/secure")
	showListConnectedDevice()
}

func initializeMQTT() mqtt.Client {
	var opts = mqtt.NewClientOptions()
	opts.AddBroker(ipOpenHAB + ":1883")
	opts.SetClientID("go-controller")
	opts.SetUsername("agent-controller")
	opts.SetPassword("12345")

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

	// test
	//agentPublishHandler("agent-controller/command", "{\"command\":\"device-add\",\"content\":\"device2\"}")
	agentPublishHandler("agent-controller/command", "{\"command\":\"device-add\",\"content\":\"device3\"}")
	<-keepAlive
}

func main() {
	// get env
	var agentIDentity AgentIdentity
	agentIDentity.AgentID = os.Getenv("agentID")
	agentIDentity.AgentName = os.Getenv("agentName")
	ListConnectedDevice = make(map[string]Agent)
	mainContract = db.InitApplication()
	ipOpenHAB = os.Args[1]
	fmt.Println(ipOpenHAB)
	//encryptedText := string(encryptMessage([]byte("healing heroes")))
	//result := string(decryptMessage([]byte[124,233,15,44,117,138,100,125,63,189,60,255,182,212,235,144,93,95,129,164,19,100,125,98,147,158,57,161,170,3,251,165,178,207,150,57,153,95,126,20,255,201,120,50,147,146,143,139,107,166,5,96,249,139,42,232,187,102,180,40,244,149,129,26,229,66,241,236,14,74,180,4,201,170,66,67,197,123,255,8,215,216,109,6,109,41,204,153,49,129,248,157,212,201,50,255,224,71,169,251,30,7,45,6,119,131,219,253,242,164,152,250,87,138,186,2,29,16,63,54,241,131,21,16,219,199,15,246,67,179,0,72,26,103,142,74,46,246,44,223,217,110,10,127,118,131,202,169,52,7,215,174,106,25,22,3,192,219,135,27,252,239,178,120,205,102,215,254,174,235,185,248,141,26,135,5,57,198,232,211,179,107,150,21,98,229,221,54,173,57,54,166,91,14,108,181,80,76,213,26,177,155,26,41,25,67,242,145,36,198,41,65,76,235,245,212,187,190,16,219,251,177,143,70,99,21,145,0,218,196,123,138,233,9,198,189,148,199,136,149,41,202,247,4,15,110,27,209,74,63,36,108,109,73,201,178,62,252,92,188,208,59,117,212,202,78,204,218,50,166,214,216,255,102,86,22,221,234,178,58,68,161,35,241,7,28,161,202,201,206,6,204,88,29,101,84,83,100,151,56,74,239,155,66,153,237,131,69,66,140,103,55,32,36,93,60,213,66,70,212,157,179,105,72,69,55,40,219,118,11,123,18,23,191,127,142,69,254,23,47,130,32,153,63]))

	//fmt.Println(" result : " + result)
	//encResult := []byte(encryptedText)
	//fmt.Print(" chipertext gcm : ")
	//fmt.Println(encResult)
	//example := []byte{[166 140 46 163 97 12 70 67 208 239 63 153 169 63 172 63 79 119 11 45 101 128 177 165 173 97 178 250 175 102 106 209 65 11 239 113 232 247 123 21 203 3 19 242 177 17 132 227 222 186 121 59 129 127 182 29 154 157 197 166 100 26 235 245 164 174 8 104 34 152 8 20 184 247 27 201 39 243 225 23 210 159 232 147 62 94 209 102 182 114 18 189 69 58 25 44 69 15 32 33 48 205 76 28 45 147 124 166 151 231 228 246 176 101 133 118 39 178 162 91 73 169 233 48 212 206 202 87 214 57 62 25 234 157 95 0 102 226 237 29 243 2 206 26 54 14 170 59 18 89 248 9 121 249 68 34 230 167 91 133 96 53 59 184 140 70 5 63 53 55 87 80 62 227 218 179 42 249 128 108 238 252 223 11 212 88 84 90 226 216 163 14 16 60 194 118 170 6 13 43 171 63 187 226 28 232 51 192 1 36 232 34 115 72 147 156 137 162 46 232 152 129 0 237 16 184 48 88 208 54 148 146 47 232 247 207 94 216 26 159 14 131 234 102 229 240 214 58 143 114 235 109 198 142 216 0 31 127 205 109 65 65 225 231 228 18 137 28 221 134 230 62 184 145 110 124 196 108 20 202 203 165 72 194 83 120 48 68 26 116 220 191 134 227 198 69 112 94 211 158 18 146 139 248 241 41 49 122 35 147 57 133 227 60 233 174 235 46 168 57 39 77 109 32 23 125 162 209 50 5 131 251 203 224 20 119 173 191 199 77 89 121 40 95 145]}
	//decryptMessage([166 140 46 163 97 12 70 67 208 239 63 153 169 63 172 63 79 119 11 45 101 128 177 165 173 97 178 250 175 102 106 209 65 11 239 113 232 247 123 21 203 3 19 242 177 17 132 227 222 186 121 59 129 127 182 29 154 157 197 166 100 26 235 245 164 174 8 104 34 152 8 20 184 247 27 201 39 243 225 23 210 159 232 147 62 94 209 102 182 114 18 189 69 58 25 44 69 15 32 33 48 205 76 28 45 147 124 166 151 231 228 246 176 101 133 118 39 178 162 91 73 169 233 48 212 206 202 87 214 57 62 25 234 157 95 0 102 226 237 29 243 2 206 26 54 14 170 59 18 89 248 9 121 249 68 34 230 167 91 133 96 53 59 184 140 70 5 63 53 55 87 80 62 227 218 179 42 249 128 108 238 252 223 11 212 88 84 90 226 216 163 14 16 60 194 118 170 6 13 43 171 63 187 226 28 232 51 192 1 36 232 34 115 72 147 156 137 162 46 232 152 129 0 237 16 184 48 88 208 54 148 146 47 232 247 207 94 216 26 159 14 131 234 102 229 240 214 58 143 114 235 109 198 142 216 0 31 127 205 109 65 65 225 231 228 18 137 28 221 134 230 62 184 145 110 124 196 108 20 202 203 165 72 194 83 120 48 68 26 116 220 191 134 227 198 69 112 94 211 158 18 146 139 248 241 41 49 122 35 147 57 133 227 60 233 174 235 46 168 57 39 77 109 32 23 125 162 209 50 5 131 251 203 224 20 119 173 191 199 77 89 121 40 95 145])
	//generatePubKey()

	priv, pubk = generateKey()

	//testTransaction(&contract)
	//SendMessageToDevice("device1")
	// run rest server
	//StartServer()
	//submitTransaction(contract)
	// using mqtt
	startMQTTClient()

	log.Println("============ application-golang ends ============")
}
