package hn

import (
	"encoding/json"
	"errors"
	"github.com/tronch0/crypt0/bigint"
	"github.com/tronch0/curv3/ecdsa/point"
	"github.com/tronch0/curv3/ecdsa/secp256k1"
	"gorm.io/gorm"
	"log"
	"math/big"
	"ppakma/osign"
	"sync"
	"time"
)

var hnDB *gorm.DB
var hnSignKey *big.Int
var hnVerifyKey *point.Point

type precomputedQueue struct {
	mu    sync.Mutex
	queue []osign.ServerPrecomputedInfo
}

// 1. create the normal secret key
type ServerSecret struct {
	Id         uint      `json:"id" gorm:"primary_key"`
	PrivateKey string    `json:"private"`
	PublicKey  string    `json:"public"`
	CreatedAt  time.Time `json:"created_at"`
	UpdatedAt  time.Time `json:"updated_at"`
}

var precomputedQueueInstance *precomputedQueue

func preparePrecomputedQueue(capacity int, key *osign.ServerSecret) {
	if precomputedQueueInstance == nil {
		precomputedQueueInstance = &precomputedQueue{
			queue: make([]osign.ServerPrecomputedInfo, 0),
		}
	}
	for i := 0; i < capacity; i++ {
		precomputedQueueInstance.queue = append(precomputedQueueInstance.queue, *osign.PrecomputeServerSign(key))
	}
}

func generateHNSignKey() {
	// if the table is not exist, create it
	if !hnDB.Migrator().HasTable(&ServerSecret{}) {
		hnDB.Migrator().CreateTable(&ServerSecret{})
	}
	// if the table is empty, generate a new key
	var count int64
	hnDB.Model(&ServerSecret{}).Count(&count)
	if count > 0 {
		// set hnSignKeyPair
		var secret ServerSecret
		if err := hnDB.First(&secret).Error; err != nil {
			panic("get secret from db failed: " + err.Error())
		}

		var sk *osign.ApiBigint
		var pk *osign.ApiEcPoint
		err := json.Unmarshal([]byte(secret.PrivateKey), &sk)
		if err != nil {
			panic("Decode privkey from json failed: " + err.Error())
		}
		err = json.Unmarshal([]byte(secret.PublicKey), &pk)
		if err != nil {
			panic("Decode pubkey from json failed: " + err.Error())
		}

		hnSignKey = &sk.Value
		hnVerifyKey = osign.ParseEcPoint(pk)

		return
	}

	// generate an ecdsa key with secp256k1 curve
	coin := osign.GenerateRandomness()
	sk := new(big.Int).Mod(bigint.HashBytesToBigInt(coin), secp256k1.GetSecp256k1().GetN())
	pk := secp256k1.GetSecp256k1().GetG().ScalarMul(sk)

	jsonSk, err := json.Marshal(&osign.ApiBigint{Value: *sk})
	if err != nil {
		panic("Encode keypair to json failed: " + err.Error())
	}
	jsonPk, err := json.Marshal(&osign.ApiEcPoint{
		X: *pk.GetX().GetNum(),
		Y: *pk.GetY().GetNum(),
	})
	if err != nil {
		panic("Encode keypair to json failed: " + err.Error())
	}

	// save the keypair to db
	secret := &ServerSecret{
		PrivateKey: string(jsonSk),
		PublicKey:  string(jsonPk),
	}
	if err := hnDB.Create(secret).Error; err != nil {
		panic("create secret to db failed: " + err.Error())
	}

	hnSignKey = sk
	hnVerifyKey = pk
}

// 2. ue table
type UEAccount struct {
	Id         uint      `json:"id" gorm:"primary_key"`
	Supi       string    `json:"supi" gorm:"unique"`
	PrivateKey string    `json:"private_key" gorm:"unique"`
	PublicKey  string    `json:"public_key"`
	CreatedAt  time.Time `json:"created_at"`
	UpdatedAt  time.Time `json:"updated_at"`
}

func createUEAccount(supi string) (*UEAccount, error) {
	var count int64
	// check if supi is already exist
	hnDB.Model(&UEAccount{}).Where("supi = ?", supi).Count(&count)
	if count > 0 {
		log.Default().Println("supi already exist")
		ue, err := getUEAccount(supi)
		if err != nil {
			return nil, errors.New("get ue account failed: " + err.Error())
		}
		return ue, nil
	}

	serverKeyPair := osign.GenerateServerKeys()

	encodedSecret := &osign.ApiServerPriveKey{
		X: *serverKeyPair.PrivKey.X,
		Q: *osign.EncodeEcPoint(serverKeyPair.PrivKey.Q),
	}
	jsonEncodedSecret, err := json.Marshal(encodedSecret)
	if err != nil {
		return nil, errors.New("Encode privkey to json failed: " + err.Error())
	}

	encodedPubKey := &osign.ApiServerPublicKey{
		Q: *osign.EncodeEcPoint(serverKeyPair.PubKey.Q),
		Pi: osign.ApiDLogProof{
			R: *osign.EncodeEcPoint(serverKeyPair.PubKey.Pi.R),
			C: *serverKeyPair.PubKey.Pi.C,
			S: *serverKeyPair.PubKey.Pi.S,
		},
	}
	jsonEncodedPubKey, err := json.Marshal(encodedPubKey)
	if err != nil {
		return nil, errors.New("Encode pubkey to json failed: " + err.Error())
	}

	ue := &UEAccount{
		Supi:       supi,
		PrivateKey: string(jsonEncodedSecret),
		PublicKey:  string(jsonEncodedPubKey),
	}

	if err := hnDB.Create(ue).Error; err != nil {
		return nil, errors.New("create ue to db failed: " + err.Error())
	}

	return ue, nil
}

func getUEAccount(supi string) (*UEAccount, error) {
	var ue UEAccount
	err := hnDB.First(&ue, "supi = ?", supi).Error
	if err != nil {
		return nil, errors.New("get ue account failed: " + err.Error())
	}
	return &ue, nil
}
