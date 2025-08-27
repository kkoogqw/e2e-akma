package osign

import (
	"bytes"
	"crypto/sha256"
	"errors"
	"github.com/tronch0/crypt0/bigint"
	"github.com/tronch0/crypt0/paillier"
	"github.com/tronch0/curv3/ecdsa"
	"github.com/tronch0/curv3/ecdsa/point"
	"github.com/tronch0/curv3/ecdsa/secp256k1"
	"math/big"
)

type ServerPrecomputedInfo struct {
	// sign1
	K2 *big.Int
	R2 *point.Point
	Pi *DlogProof
	// sign2
	K2Inv *big.Int
	PQ    *big.Int
	V_    *big.Int
}

func PrecomputeServerSign(key *ServerSecret) *ServerPrecomputedInfo {
	pre := new(ServerPrecomputedInfo)
	// random k2 from Zq
	coin := GenerateRandomness()
	pre.K2 = new(big.Int).Mod(bigint.HashBytesToBigInt(coin), secp256k1.GetSecp256k1().GetN())
	// R2 = G^k1
	pre.R2 = secp256k1.GetSecp256k1().GetG().ScalarMul(pre.K2)
	// proof
	pre.Pi = NewDlogProof(ecdsa.NewPrivateKey(secp256k1.GetSecp256k1(), pre.K2), pre.R2)

	// sign2
	pre.K2Inv = new(big.Int).ModInverse(pre.K2, secp256k1.GetSecp256k1().GetN())

	phoCoin := GenerateRandomness()
	pho := new(big.Int).Mod(bigint.HashBytesToBigInt(phoCoin), secp256k1.GetSecp256k1().GetN())
	pre.PQ = new(big.Int).Mul(pho, secp256k1.GetSecp256k1().GetN())

	pre.V_ = new(big.Int).Mul(pre.K2Inv, key.X)

	return pre
}

func AmortizedServerSign1(clientComm []byte, preComputed *ServerPrecomputedInfo) (*ServerState, *ServerPublicKey) {
	st := &ServerState{
		K2:   preComputed.K2,
		R2:   preComputed.R2,
		Comm: clientComm,
	}
	k := &ServerPublicKey{
		Q:  preComputed.R2,
		Pi: preComputed.Pi,
	}
	return st, k
}

func AmortizedServerSign2(key *ServerSecret, st *ServerState, preSig *ClientPreSign, preComputed *ServerPrecomputedInfo) (*ServerPreSign, error) {
	// check the commit
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

	// compute the R = k2 * R1
	R := preSig.R.ScalarMul(st.K2)
	r := new(big.Int).Mod(R.GetX().GetNum(), secp256k1.GetSecp256k1().GetN())

	// v = k2^{-1} * r * x2 = _v * r
	v := new(big.Int).Mul(preComputed.V_, r)
	w := new(big.Int).Mul(preComputed.K2Inv, preSig.M)
	w = new(big.Int).Add(w, preComputed.PQ)
	w = new(big.Int).Mod(w, secp256k1.GetSecp256k1().GetN())

	ct := paillier.Mul(preSig.PailliarPubKey, preSig.EncKey, v.Bytes())
	c3, err := paillier.Add(preSig.PailliarPubKey, ct, w.Bytes())
	if err != nil {
		return nil, err
	}

	sPreSig := &ServerPreSign{
		Ct: c3,
	}

	return sPreSig, nil
}
