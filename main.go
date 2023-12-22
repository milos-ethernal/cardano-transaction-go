package main

import (
	"bytes"
	"encoding/hex"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"

	"github.com/fivebinaries/go-cardano-serialization/address"
	"github.com/fivebinaries/go-cardano-serialization/bip32"
	"github.com/fivebinaries/go-cardano-serialization/network"
	"github.com/fivebinaries/go-cardano-serialization/node"
	"github.com/fivebinaries/go-cardano-serialization/tx"
	"github.com/joho/godotenv"
	"github.com/safanaj/cardano-go"
	"github.com/safanaj/cardano-go/crypto"
)

// uses github.com/safanaj/cardano-go
// returns witness error when submiting the transaction
// problem with private key generation, prob with format
// https://github.com/safanaj/cardano-go/issues/4
func create_simple_transaction_ver1() []byte {
	txBuilder := cardano.NewTxBuilder(&cardano.ProtocolParams{
		MinFeeA:            44,
		MinFeeB:            155381,
		MaxBlockBodySize:   90112,
		MaxTxSize:          16384,
		MaxBlockHeaderSize: 1100,
		KeyDeposit:         2000000,
		PoolDeposit:        500000000,
		MaxEpoch:           18,
		NOpt:               0,
		PoolPledgeInfluence: cardano.Rational{
			P: 1,
			Q: 3,
		},
		ExpansionRate: cardano.Rational{
			P: 3,
			Q: 1000,
		},
		TreasuryGrowthRate: cardano.Rational{},
		D:                  cardano.Rational{},
		ExtraEntropy:       []byte{},
		ProtocolVersion: cardano.ProtocolVersion{
			Major: 8,
			Minor: 0,
		},
		MinPoolCost:          170000000,
		CoinsPerUTXOWord:     4310,
		CostModels:           nil,
		ExecutionCosts:       nil,
		MaxTxExUnits:         nil,
		MaxBlockTxExUnits:    nil,
		MaxValueSize:         5000,
		CollateralPercentage: 150,
		MaxCollateralInputs:  3,
	})

	sender, err := cardano.NewAddress("addr_test1vpe3gtplyv5ygjnwnddyv0yc640hupqgkr2528xzf5nms7qalkkln")
	if err != nil {
		panic(err)
	}

	receiver, err := cardano.NewAddress("addr_test1vptkepz8l4ze03478cvv6ptwduyglgk6lckxytjthkvvluc3dewfd")
	if err != nil {
		panic(err)
	}

	// seed, _ := hex.DecodeString("085de0735c76409f64a704e05eafdccd49f733a1dffea5e5bd514c6904179e9480000000000000000000000000000000000000000000000000000000000000000")
	// var sk crypto.PrvKey = seed

	sk, err := crypto.NewPrvKey("ed25519_sk1ppw7qu6uweqf7e98qns9at7ue4ylwvapmll2teda29xxjpqhn62qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqq4lqx8l")
	if err != nil {
		panic(err)
	}

	println(sk.PubKey().Bech32("ed25519_pk"))

	// key := ed25519.NewKeyFromSeed(seed)
	// key.Public()

	txHash, err := cardano.NewHash32("2d9b42a1dd7f01e26b4fe8de9d2d5dfe94576420457ad2a115085190ba3a01fa")
	if err != nil {
		panic(err)
	}

	txInput := cardano.NewTxInput(txHash, 1, cardano.NewValue(9997281236))
	txOut := cardano.NewTxOutput(receiver, cardano.NewValue(1000000))

	txBuilder.AddInputs(txInput)
	txBuilder.AddOutputs(txOut)
	txBuilder.SetTTL(436425231)
	txBuilder.AddChangeIfNeeded(sender)
	txBuilder.Sign(sk)

	tx, err := txBuilder.Build()
	if err != nil {
		panic(err)
	}

	return tx.Bytes()
}

// required for create_simple_transaction_ver2
func harden(num uint) uint32 {
	return uint32(0x80000000 + num)
}

// required for create_simple_transaction_ver2
func generateBaseAddress(net *network.NetworkInfo, rootKey bip32.XPrv) (addr *address.BaseAddress, utxoPrvKey bip32.XPrv, err error) {
	accountKey := rootKey.Derive(harden(1852)).Derive(harden(1815)).Derive(harden(0))

	utxoPrvKey = accountKey.Derive(0).Derive(0)
	utxoPubKey := utxoPrvKey.Public()
	utxoPubKeyHash := utxoPubKey.PublicKey().Hash()

	stakeKey := accountKey.Derive(2).Derive(0).Public()
	stakeKeyHash := stakeKey.PublicKey().Hash()

	addr = address.NewBaseAddress(
		net,
		&address.StakeCredential{
			Kind:    address.KeyStakeCredentialType,
			Payload: utxoPubKeyHash[:],
		},
		&address.StakeCredential{
			Kind:    address.KeyStakeCredentialType,
			Payload: stakeKeyHash[:],
		})
	return
}

// uses github.com/fivebinaries/go-cardano-serialization
// for cli(Blockfrost API) calls it is necessary to edit
// NewBlockfrostClient method in line 131 to serverUrl = blockfrost.CardanoPreview
func create_simple_transaction_ver2() ([]byte, error) {
	// Load env variables
	err := godotenv.Load()
	if err != nil {
		log.Fatalf("err loading: %v", err)
	}

	cli := node.NewBlockfrostClient(
		os.Getenv("BLOCKFROST_PROJECT_ID"),
		network.TestNet(),
	)

	pr, err := cli.ProtocolParameters()
	if err != nil {
		panic(err)
	}

	seed, _ := hex.DecodeString("085de0735c76409f64a704e05eafdccd49f733a1dffea5e5bd514c6904179e948")
	pk, err := bip32.NewXPrv(seed)
	if err != nil {
		panic(err)
	}

	sender, err := address.NewAddress("addr_test1vpe3gtplyv5ygjnwnddyv0yc640hupqgkr2528xzf5nms7qalkkln")
	if err != nil {
		panic(err)
	}

	receiver, err := address.NewAddress("addr_test1vptkepz8l4ze03478cvv6ptwduyglgk6lckxytjthkvvluc3dewfd")
	if err != nil {
		panic(err)
	}

	// Get the senders available UTXOs
	utxos, err := cli.UTXOs(sender)
	if err != nil {
		panic(err)
	}

	builder := tx.NewTxBuilder(
		pr,
		[]bip32.XPrv{pk},
	)

	// Send 1000000 lovelace or 1 ADA
	sendAmount := 1000000
	var firstMatchInput tx.TxInput

	// Loop through utxos to find first input with enough ADA
	for _, utxo := range utxos {
		minRequired := sendAmount + 1000000 + 200000
		if utxo.Amount >= uint(minRequired) {
			firstMatchInput = utxo
		}
	}

	// Add the transaction Input / UTXO
	builder.AddInputs(&firstMatchInput)

	// Add a transaction output with the receiver's address and amount of 1 ADA
	builder.AddOutputs(tx.NewTxOutput(
		receiver,
		uint(sendAmount),
	))

	// Query tip from a node on the network. This is to get the current slot
	// and compute TTL of transaction.
	tip, err := cli.QueryTip()
	if err != nil {
		log.Fatal(err)
	}

	// Set TTL for 5 min into the future
	builder.SetTTL(uint32(tip.Slot) + uint32(300))

	// Route back the change to the source address
	// This is equivalent to adding an output with the source address and change amount
	builder.AddChangeIfNeeded(sender)

	// Build loops through the witness private keys and signs the transaction body hash
	txFinal, err := builder.Build()
	if err != nil {
		log.Fatal(err)
	}

	return txFinal.Bytes()

	// txHash, err := cli.SubmitTx(txFinal)
	// if err != nil {
	// 	log.Fatal(err)
	// }

	// fmt.Println(txHash)
}

func submit_transaction_api(transaction []byte) {
	// Set up the URL for the cardano-submit-api
	url := "http://localhost:8090/api/submit/tx"

	// Create a new HTTP client
	client := &http.Client{}

	// Send the POST request with the CBOR-encoded transaction data
	resp, err := client.Post(url, "application/cbor", bytes.NewBuffer(transaction))
	if err != nil {
		fmt.Println("Error:", err)
		return
	}
	defer resp.Body.Close()

	// Read the response body
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		fmt.Println("Error reading response:", err)
		return
	}

	// Print the response status code and body
	fmt.Println("Status Code:", resp.Status)
	fmt.Println("Response Body:", string(body))
}

func main() {
	fmt.Println("Test create_simple_transaction")

	transaction, err := create_simple_transaction_ver2()
	if err != nil {
		panic(err)
	}

	fmt.Println("Test submit_transaction_api")

	submit_transaction_api(transaction)
}
