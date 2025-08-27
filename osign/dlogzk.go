package osign

import (
	"crypto/sha256"
	"fmt"
	"math/big"

	"github.com/tronch0/crypt0/bigint"
	"github.com/tronch0/curv3/ecdsa"
	"github.com/tronch0/curv3/ecdsa/point"
	"github.com/tronch0/curv3/ecdsa/secp256k1"
)

func GenerateRandomness() []byte {
	r1 := bigint.GetRandom().String()
	r2 := bigint.GetRandom().String()
	r := fmt.Sprintf("%s%s", r1, r2)
	hash := sha256.New()
	hash.Write([]byte(r))
	return hash.Sum(nil)
}

type DlogProof struct {
	R *point.Point
	S *big.Int
	C *big.Int
}

func NewDlogProof(sec *ecdsa.PrivateKey, pub *point.Point) *DlogProof {
	// random r from Zq
	coin := GenerateRandomness()
	r := new(big.Int).Mod(bigint.HashBytesToBigInt(coin), secp256k1.GetSecp256k1().GetN())
	// R = G^r
	G := secp256k1.GetSecp256k1().GetG()
	R := G.ScalarMul(r)
	// c = H(R, pub, m)
	rBytes := append(
		R.GetX().GetNum().Bytes(),
		R.GetY().GetNum().Bytes()...)
	pubBytes := append(
		pub.GetX().GetNum().Bytes(),
		pub.GetY().GetNum().Bytes()...)
	gBytes := append(
		G.GetX().GetNum().Bytes(),
		G.GetY().GetNum().Bytes()...)
	ch := append(rBytes, append(pubBytes, gBytes...)...)
	c := bigint.HashBytesToBigInt(ch)
	// s = r + c * sec
	s := new(big.Int).Add(r, new(big.Int).Mul(c, sec.Key))
	return &DlogProof{R, s, c}

}

func (p *DlogProof) Verify(pub *point.Point) bool {
	// compute ch
	rBytes := append(
		p.R.GetX().GetNum().Bytes(),
		p.R.GetY().GetNum().Bytes()...)
	pubBytes := append(
		pub.GetX().GetNum().Bytes(),
		pub.GetY().GetNum().Bytes()...)
	gBytes := append(
		secp256k1.GetSecp256k1().GetG().GetX().GetNum().Bytes(),
		secp256k1.GetSecp256k1().GetG().GetY().GetNum().Bytes()...)
	ch := append(rBytes, append(pubBytes, gBytes...)...)
	c := bigint.HashBytesToBigInt(ch)
	if c.Cmp(p.C) != 0 {
		return false
	}
	// R = G^s * pub^-c
	G := secp256k1.GetSecp256k1().GetG()
	sG := G.ScalarMul(p.S)
	pub_ := pub.ScalarMul(c)
	R_ := p.R.Add(pub_)

	if R_.Equal(sG) == false {
		return false
	}
	return true
}
