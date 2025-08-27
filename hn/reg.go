package hn

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"github.com/tronch0/curv3/ecdsa"
	"github.com/tronch0/curv3/ecdsa/secp256k1"
	"golang.org/x/crypto/openpgp/elgamal"
	"math/big"
	"ppakma/osign"
	"sync"
)

const CorePubKeyPrimeHex = "B10B8F96A080E01DDE92DE5EAE5D54EC52C99FBCFB06A3C69A6A9DCA52D23B616073E28675A23D189838EF1E2EE652C013ECB4AEA906112324975C3CD49B83BFACCBDD7D90C4BD7098488E9C219A73724EFFD6FAE5644738FAA31A4FF55BCCC0A151AF5F0DC8B4BD45BF37DF365C1A65E68CFDA76D4DA708DF1FB2BC2E4A4371"

const CorePubKeyGenHex = "A4D1CBD5C3FD34126765A442EFB99905F8104DD258AC507FD6406CFF14266D31266FEA1E5C41564B777E690F5504F213160217B4B01B886A5E91547F9E2749F4D7FBD7D3B9A92EE1909D0D2263F80A76A6A24C087A091F531DBF0A0169B6A28AD662A4D18E73AFA32D779D5918D08BC8858F4DCEF97C2A24855E6EEB22B3B2E5"

type registerSession struct {
	Supi         string
	OsignPrivKey string
	OsignPubKey  string
	OsignState   *osign.ServerState
}

// var registerSessions = make(map[string]registerSession)
var registerSessions2 sync.Map

type ClientRegisterCommitRequest struct {
	Supi        string `json:"supi"`
	CommitUID   string `json:"commit_uid"`
	CommitOsKey string `json:"commit_os_key"`
}

type ClientRegisterFinishRequest struct {
	Supi     string                  `json:"supi"`
	PreOsign *osign.ApiClientPreSign `json:"pre_osign"`
}

type ClientRegisterTag struct {
	C1 *big.Int `json:"c_1"`
	C2 *big.Int `json:"c_2"`
}

func ueRegistrationRequest(supi string) (*osign.ApiServerPriveKey, *osign.ApiServerPublicKey, error) {
	ue, err := createUEAccount(supi)
	if err != nil {
		return nil, nil, err
	}
	var sk osign.ApiServerPriveKey
	var pk osign.ApiServerPublicKey
	err = json.Unmarshal([]byte(ue.PrivateKey), &sk)
	if err != nil {
		return nil, nil, err
	}
	err = json.Unmarshal([]byte(ue.PublicKey), &pk)
	if err != nil {
		return nil, nil, err
	}
	// set session state
	newSessioin := registerSession{
		Supi:         supi,
		OsignPrivKey: ue.PrivateKey,
		OsignPubKey:  ue.PublicKey,
		OsignState:   nil,
	}
	registerSessions2.Store(supi, newSessioin)
	return &sk, &pk, nil
}

func ueRegistrationCommit(supi string, commit string) (*ecdsa.Signature, *ClientRegisterTag, error) {
	pk := elgamal.PublicKey{
		G: fromHex(CorePubKeyGenHex),
		P: fromHex(CorePubKeyPrimeHex),
	}
	c_1, c_2, err := elgamal.Encrypt(rand.Reader, &pk, []byte(supi))
	if err != nil {
		return nil, nil, err
	}

	signKey := ecdsa.NewPrivateKey(secp256k1.GetSecp256k1(), hnSignKey)
	sigma := ecdsa.Sign(signKey, commit, secp256k1.GetSecp256k1())

	tag := &ClientRegisterTag{
		C1: c_1,
		C2: c_2,
	}
	return sigma, tag, nil
}

func ueRegistrationSign(supi string, clientOsignComm string) (*osign.ApiEcPoint, *osign.ApiDLogProof, error) {

	// check session
	value, ok := registerSessions2.Load(supi)
	if !ok {
		return nil, nil, errors.New("session not found")
	}
	session := value.(registerSession)

	// check state
	clientComm, err := hex.DecodeString(clientOsignComm)
	if err != nil {
		// delete session
		//delete(registerSessions, supi)
		registerSessions2.Delete(supi)
		return nil, nil, err
	}

	osState, ostpk := osign.ServerSign1(clientComm)
	session.OsignState = osState

	point := osign.EncodeEcPoint(ostpk.Q)
	proof := &osign.ApiDLogProof{
		R: *osign.EncodeEcPoint(ostpk.Pi.R),
		C: *ostpk.Pi.C,
		S: *ostpk.Pi.S,
	}

	registerSessions2.Store(supi, session)

	return point, proof, nil
}

func ueRegistrationFinish(supi string, preSign *osign.ClientPreSign) (*osign.ServerPreSign, error) {
	value, ok := registerSessions2.Load(supi)
	if !ok {
		return nil, errors.New("session not found")
	}
	session := value.(registerSession)

	var osSecret osign.ApiServerPriveKey
	err := json.Unmarshal([]byte(session.OsignPrivKey), &osSecret)
	if err != nil {
		registerSessions2.Delete(supi)
		return nil, err
	}

	sig, err := osign.ServerSign2(
		&osign.ServerSecret{
			X: &osSecret.X,
			Q: osign.ParseEcPoint(&osSecret.Q),
		},
		session.OsignState,
		preSign)
	registerSessions2.Delete(supi)
	if err != nil {
		return nil, err
	}
	return sig, nil
}

func fromHex(hex string) *big.Int {
	n, ok := new(big.Int).SetString(hex, 16)
	if !ok {
		panic("failed to parse hex number")
	}
	return n
}
