package osign

import (
	"bytes"
	"crypto/sha256"
	"errors"
	"log"
	"math/big"
	"time"

	"github.com/tronch0/crypt0/bigint"
	"github.com/tronch0/crypt0/paillier"
	"github.com/tronch0/curv3/ecdsa"
	"github.com/tronch0/curv3/ecdsa/point"
	"github.com/tronch0/curv3/ecdsa/secp256k1"
)

type ServerSecret struct {
	X *big.Int
	Q *point.Point
}

type ServerPublicKey struct {
	Q  *point.Point
	Pi *DlogProof
}

type ServerKeyGenResult struct {
	PrivKey *ServerSecret
	PubKey  *ServerPublicKey
}

type ServerState struct {
	K2   *big.Int
	R2   *point.Point
	Ct   *big.Int
	Comm []byte
}

// server key Generation
func GenerateServerKeys() *ServerKeyGenResult {
	// random k2 from Zq
	coin := GenerateRandomness()
	x2 := new(big.Int).Mod(bigint.HashBytesToBigInt(coin), secp256k1.GetSecp256k1().GetN())
	Q2 := secp256k1.GetSecp256k1().GetG().ScalarMul(x2)
	sk := &ServerSecret{
		X: x2,
		Q: Q2,
	}
	pf := NewDlogProof(ecdsa.NewPrivateKey(secp256k1.GetSecp256k1(), x2), Q2)
	pk := &ServerPublicKey{
		Q:  Q2,
		Pi: pf,
	}
	return &ServerKeyGenResult{
		PrivKey: sk,
		PubKey:  pk,
	}
}

// server sign
// message 1
func ServerSign1(clientComm []byte) (*ServerState, *ServerPublicKey) {
	// random k2 from Zq
	coin := GenerateRandomness()
	k2 := new(big.Int).Mod(bigint.HashBytesToBigInt(coin), secp256k1.GetSecp256k1().GetN())
	// R2 = G^k1
	R2 := secp256k1.GetSecp256k1().GetG().ScalarMul(k2)
	// proof
	pf := NewDlogProof(ecdsa.NewPrivateKey(secp256k1.GetSecp256k1(), k2), R2)

	st := &ServerState{
		K2:   k2,
		R2:   R2,
		Comm: clientComm,
	}
	k := &ServerPublicKey{
		Q:  R2,
		Pi: pf,
	}
	return st, k
}

// message 2
type ServerPreSign struct {
	Ct []byte
}

func ServerSign2(key *ServerSecret, st *ServerState, preSig *ClientPreSign) (*ServerPreSign, error) {
	// check the commit
	vfStart := time.Now()
	r1Bytes := append(
		preSig.R.GetX().GetNum().Bytes(),
		preSig.R.GetY().GetNum().Bytes()...)
	piRBytes := append(
		preSig.Pi.R.GetX().GetNum().Bytes(),
		preSig.Pi.R.GetY().GetNum().Bytes()...)
	piSBytes := preSig.Pi.S.Bytes()
	piCBytes := preSig.Pi.C.Bytes()
	ch := append(r1Bytes, append(piRBytes, append(piSBytes, piCBytes...)...)...)

	commit := sha256.New()
	commit.Write(ch)
	comm := commit.Sum(nil)

	if !bytes.Equal(comm, st.Comm) {
		return nil, errors.New("invalid commit")
	}
	// verify the proof
	vf := preSig.Pi.Verify(preSig.R)
	if !vf {
		return nil, errors.New("invalid proof")
	}
	// compute timer
	vfEnd := time.Now()
	log.Default().Println("verify time: ", vfEnd.Sub(vfStart))

	// compute the R = k2 * R1
	rcomputeStart := time.Now()
	R := preSig.R.ScalarMul(st.K2)
	r := new(big.Int).Mod(R.GetX().GetNum(), secp256k1.GetSecp256k1().GetN())
	rcomputeEnd := time.Now()
	log.Default().Println("r compute time: ", rcomputeEnd.Sub(rcomputeStart))

	// v = k2^{-1} * r * x2
	vcomputeStart := time.Now()
	kInverse := new(big.Int).ModInverse(st.K2, secp256k1.GetSecp256k1().GetN())
	v := new(big.Int).Mul(kInverse, r)
	v = new(big.Int).Mul(v, key.X)
	vcomputeEnd := time.Now()
	log.Default().Println("v compute time: ", vcomputeEnd.Sub(vcomputeStart))

	// w = k2^-1 * m + pq
	wcomputeStart := time.Now()
	phoCoin := GenerateRandomness()
	pho := new(big.Int).Mod(bigint.HashBytesToBigInt(phoCoin), secp256k1.GetSecp256k1().GetN())
	pq := new(big.Int).Mul(pho, secp256k1.GetSecp256k1().GetN())
	w := new(big.Int).Mul(kInverse, preSig.M)
	w = new(big.Int).Add(w, pq)
	w = new(big.Int).Mod(w, secp256k1.GetSecp256k1().GetN())
	wcomputeEnd := time.Now()
	log.Default().Println("w compute time: ", wcomputeEnd.Sub(wcomputeStart))

	homomorphicMulStart := time.Now()
	ct := paillier.Mul(preSig.PailliarPubKey, preSig.EncKey, v.Bytes())
	homomorphicMulEnd := time.Now()
	log.Default().Println("homomorphic mul time: ", homomorphicMulEnd.Sub(homomorphicMulStart))

	homomorphicAddStart := time.Now()
	c3, err := paillier.Add(preSig.PailliarPubKey, ct, w.Bytes())
	homomorphicAddEnd := time.Now()
	log.Default().Println("homomorphic add time: ", homomorphicAddEnd.Sub(homomorphicAddStart))

	if err != nil {
		return nil, err
	}

	sPreSig := &ServerPreSign{
		Ct: c3,
	}

	return sPreSig, nil
}
