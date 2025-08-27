package osign

import (
	"crypto/rand"
	"crypto/sha256"
	"errors"
	"github.com/tronch0/crypt0/bigint"
	"github.com/tronch0/crypt0/paillier"
	"github.com/tronch0/curv3/ecdsa"
	"github.com/tronch0/curv3/ecdsa/point"
	"github.com/tronch0/curv3/ecdsa/secp256k1"
	"math/big"
)

type ClientPrecomputedInfo struct {
	K1     *big.Int
	R1     *point.Point
	Pi     *DlogProof
	Com    []byte
	Paikey *paillier.PrivateKey
	CtHE   []byte
}

// prepare n precomputed data set for client sign
func PrecomputeClientSign(key *ClientKey) (*ClientPrecomputedInfo, error) {
	aux := new(ClientPrecomputedInfo)
	// random k1 from Zq
	coin := GenerateRandomness()
	aux.K1 = new(big.Int).Mod(bigint.HashBytesToBigInt(coin), secp256k1.GetSecp256k1().GetN())
	// R1 = G^k1
	aux.R1 = secp256k1.GetSecp256k1().GetG().ScalarMul(aux.K1)
	// gen proof
	aux.Pi = NewDlogProof(ecdsa.NewPrivateKey(secp256k1.GetSecp256k1(), aux.K1), aux.R1)
	// commit R1 and pi1 using sha256
	r1Bytes := append(
		aux.R1.GetX().GetNum().Bytes(),
		aux.R1.GetY().GetNum().Bytes()...)
	piRBytes := append(
		aux.Pi.R.GetX().GetNum().Bytes(),
		aux.Pi.R.GetY().GetNum().Bytes()...)
	piSBytes := aux.Pi.S.Bytes()
	piCBytes := aux.Pi.C.Bytes()

	ch := append(r1Bytes, append(piRBytes, append(piSBytes, piCBytes...)...)...)
	commit := sha256.New()
	commit.Write(ch)
	aux.Com = commit.Sum(nil)

	// generate a paillier key pair
	pailliarKeyPair, err := paillier.GenerateKey(rand.Reader)
	if err != nil {
		return nil, err
	} else {
		aux.Paikey = pailliarKeyPair
	}
	encX, err := paillier.Encrypt(&pailliarKeyPair.PublicKey, key.X.Bytes())
	if err != nil {
		return nil, err
	} else {
		aux.CtHE = encX
	}

	return aux, nil
}

func AmortizedClientSign1(pre *ClientPrecomputedInfo) (*ClientState, *[]byte) {
	st := &ClientState{
		K1: pre.K1,
		R1: pre.R1,
		Pi: pre.Pi,
	}
	return st, &pre.Com
}

func AmortizedClientSign2(msg []byte, key *ClientKey, st *ClientState, serverPubKey *ServerPublicKey, pre *ClientPrecomputedInfo) (*ClientState, *ClientPreSign, error) {
	// verify server proof
	vf := serverPubKey.Pi.Verify(serverPubKey.Q)
	if !vf {
		return nil, nil, errors.New("invalid server proof")
	}
	// commit msg
	m := bigint.HashBytesToBigInt(msg)

	newSt := &ClientState{
		K1:     st.K1,
		R1:     st.R1,
		R2:     serverPubKey.Q,
		Pi:     st.Pi,
		Paikey: pre.Paikey,
		Ct:     pre.CtHE,
	}

	preSig := &ClientPreSign{
		EncKey:         pre.CtHE,
		M:              m,
		R:              st.R1,
		Pi:             st.Pi,
		PailliarPubKey: &pre.Paikey.PublicKey,
	}

	return newSt, preSig, nil
}

func AmortizedClientFinal() {} // no changed
