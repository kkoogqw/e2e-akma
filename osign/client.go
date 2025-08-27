package osign

import (
	"crypto/rand"
	"crypto/sha256"
	"errors"
	"math/big"

	"github.com/tronch0/crypt0/bigint"
	"github.com/tronch0/crypt0/paillier"
	"github.com/tronch0/curv3/ecdsa"
	"github.com/tronch0/curv3/ecdsa/point"
	"github.com/tronch0/curv3/ecdsa/secp256k1"
)

type ClientKey struct {
	X *big.Int
	Q *point.Point
}

type ClientState struct {
	K1     *big.Int
	R1     *point.Point
	R2     *point.Point
	Pi     *DlogProof
	Paikey *paillier.PrivateKey
	Ct     []byte
}

// client key Generation
func GenerateClientKeys(serverPubKey *ServerPublicKey) (*ClientKey, error) {
	vf := serverPubKey.Pi.Verify(serverPubKey.Q)
	if !vf {
		return nil, errors.New("Failed to verify the Public Key of Server.")
	}
	// random k1 from Zq
	coin := GenerateRandomness()
	x1 := new(big.Int).Mod(bigint.HashBytesToBigInt(coin), secp256k1.GetSecp256k1().GetN())
	Q1 := serverPubKey.Q.ScalarMul(x1)

	key := &ClientKey{
		X: x1,
		Q: Q1,
	}
	return key, nil
}

// client sign
// message 1

func ClientSign1() (*ClientState, *[]byte) {
	// random k1 from Zq
	coin := GenerateRandomness()
	k1 := new(big.Int).Mod(bigint.HashBytesToBigInt(coin), secp256k1.GetSecp256k1().GetN())
	// R1 = G^k1
	R1 := secp256k1.GetSecp256k1().GetG().ScalarMul(k1)
	// gen proof
	pi := NewDlogProof(ecdsa.NewPrivateKey(secp256k1.GetSecp256k1(), k1), R1)
	// commit R1 and pi1 using sha256
	r1Bytes := append(
		R1.GetX().GetNum().Bytes(),
		R1.GetY().GetNum().Bytes()...)
	piRBytes := append(
		pi.R.GetX().GetNum().Bytes(),
		pi.R.GetY().GetNum().Bytes()...)
	piSBytes := pi.S.Bytes()
	piCBytes := pi.C.Bytes()

	ch := append(r1Bytes, append(piRBytes, append(piSBytes, piCBytes...)...)...)
	commit := sha256.New()
	commit.Write(ch)
	comm := commit.Sum(nil)
	st := &ClientState{
		K1: k1,
		R1: R1,
		Pi: pi,
	}
	// encode comm hex-bytes to string
	// c := make([]byte, len(comm))
	// copy(c, comm)

	return st, &comm
}

// message 2
type ClientPreSign struct {
	EncKey         []byte
	M              *big.Int
	R              *point.Point
	Pi             *DlogProof
	PailliarPubKey *paillier.PublicKey
}

func ClientSign2(msg []byte, key *ClientKey, st *ClientState, serverPubKey *ServerPublicKey) (*ClientState, *ClientPreSign, error) {
	// verify server proof
	vf := serverPubKey.Pi.Verify(serverPubKey.Q)
	if !vf {
		return nil, nil, errors.New("invalid server proof")
	}
	// gen paillier key
	paillierKeyPair, err := paillier.GenerateKey(rand.Reader)
	if err != nil {
		return nil, nil, err
	}
	// encrypt client key
	encX, err := paillier.Encrypt(&paillierKeyPair.PublicKey, key.X.Bytes())
	if err != nil {
		return nil, nil, err
	}
	// commit msg
	m := bigint.HashBytesToBigInt(msg)
	// update state
	newSt := &ClientState{
		K1:     st.K1,
		R1:     st.R1,
		R2:     serverPubKey.Q,
		Pi:     st.Pi,
		Paikey: paillierKeyPair,
		Ct:     encX,
	}

	preSig := &ClientPreSign{
		EncKey:         encX,
		M:              m,
		R:              st.R1,
		Pi:             st.Pi,
		PailliarPubKey: &paillierKeyPair.PublicKey,
	}

	return newSt, preSig, nil
}

func ClientFinal(st *ClientState, sPreSig *ServerPreSign) (*ecdsa.Signature, error) {
	res := &ecdsa.Signature{}
	// R = k1 * R2
	R := st.R2.ScalarMul(st.K1)
	r := new(big.Int).Mod(R.GetX().GetNum(), secp256k1.GetSecp256k1().GetN())
	res.R = r

	// decrypt
	ss, err := paillier.Decrypt(st.Paikey, sPreSig.Ct)
	if err != nil {
		return nil, err
	}

	kInverse := new(big.Int).ModInverse(st.K1, secp256k1.GetSecp256k1().GetN())
	ss_ := new(big.Int).SetBytes(ss)
	ss_ = new(big.Int).Mul(ss_, kInverse)
	ss_ = new(big.Int).Mod(ss_, secp256k1.GetSecp256k1().GetN())
	q_ss_ := new(big.Int).Sub(secp256k1.GetSecp256k1().GetN(), ss_)
	if ss_.Cmp(q_ss_) < 0 {
		res.S = ss_
	} else {
		res.S = q_ss_
	}

	return res, nil
}
