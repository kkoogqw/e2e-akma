package hn

import (
	"encoding/hex"
	"encoding/json"
	"errors"
	"ppakma/osign"
	"sync"
)

type loginSession struct {
	Supi         string
	OsignPrivKey string
	OsignPubKey  string
	OsignState   *osign.ServerState
}

// var loginSessions = make(map[string]loginSession)
var loginSessions2 sync.Map

type ClientLoginRequest struct {
	Supi   string `json:"supi"`
	Commit string `json:"commit"`
}

type ClientLoginFinishRequest struct {
	Supi     string                  `json:"supi"`
	PreOsign *osign.ApiClientPreSign `json:"pre_osign"`
}

func ueLoginRequest(supi, commit string) (*osign.ApiEcPoint, *osign.ApiDLogProof, error) {
	ue, err := getUEAccount(supi)
	if err != nil || ue == nil {
		return nil, nil, errors.New("get ue account failed. ")
	}
	clientComm, err := hex.DecodeString(commit)
	if err != nil {
		return nil, nil, errors.New("decode client commit failed. " + err.Error())
	}

	state, ostpk := osign.ServerSign1(clientComm)

	session := loginSession{
		Supi:         supi,
		OsignPrivKey: ue.PrivateKey,
		OsignPubKey:  ue.PublicKey,
		OsignState:   state,
	}
	loginSessions2.Store(supi, session)

	point := osign.EncodeEcPoint(ostpk.Q)
	proof := &osign.ApiDLogProof{
		R: *osign.EncodeEcPoint(ostpk.Pi.R),
		C: *ostpk.Pi.C,
		S: *ostpk.Pi.S,
	}
	return point, proof, nil
}

func ueLoginFinish(supi string, clientPreSign *osign.ClientPreSign) (*osign.ServerPreSign, error) {
	value, ok := loginSessions2.Load(supi)
	session := value.(loginSession)

	if !ok {
		return nil, errors.New("session not found")
	}
	var osSecret osign.ApiServerPriveKey
	err := json.Unmarshal([]byte(session.OsignPrivKey), &osSecret)
	if err != nil {
		loginSessions2.Delete(supi)
		return nil, err
	}
	sig, err := osign.ServerSign2(
		&osign.ServerSecret{
			X: &osSecret.X,
			Q: osign.ParseEcPoint(&osSecret.Q),
		},
		session.OsignState,
		clientPreSign)

	loginSessions2.Delete(supi)
	if err != nil {
		return nil, err
	}
	return sig, nil
}
