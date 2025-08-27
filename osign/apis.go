package osign

import (
	"github.com/tronch0/crypt0/field"
	"github.com/tronch0/crypt0/paillier"
	"math/big"

	"github.com/tronch0/curv3/ecdsa/point"
	"github.com/tronch0/curv3/ecdsa/secp256k1"
)

type ApiBigint struct {
	Value big.Int `json:"value"`
}

type ApiEcPoint struct {
	X big.Int `json:"x"`
	Y big.Int `json:"y"`
}

type ApiDLogProof struct {
	R ApiEcPoint `json:"r"`
	S big.Int    `json:"s"`
	C big.Int    `json:"c"`
}

func EncodeEcPoint(p *point.Point) *ApiEcPoint {
	return &ApiEcPoint{
		X: *p.GetX().GetNum(),
		Y: *p.GetY().GetNum(),
	}
}

func ParseEcPoint(p *ApiEcPoint) *point.Point {
	curve := secp256k1.GetSecp256k1()
	a := curve.GetA()
	b := curve.GetB()
	order := curve.GetP()

	ffX := field.New(&p.X, order)
	ffY := field.New(&p.Y, order)

	return point.New(ffX, ffY, a, b)
}

type ApiSignKeyPair struct {
	Pk ApiEcPoint `json:"pk"`
	Sk big.Int    `json:"sk"`
}

type ApiServerPriveKey struct {
	X big.Int    `json:"x"`
	Q ApiEcPoint `json:"q"`
}

type ApiServerPublicKey struct {
	Q  ApiEcPoint   `json:"q"`
	Pi ApiDLogProof `json:"pi"`
}

type ApiServerPreSign struct {
	Ct []byte `json:"ct"`
}

type ApiClientPrivKey struct {
	X big.Int    `json:"x"`
	Q ApiEcPoint `json:"q"`
}

type ApiClientPublicKey struct {
	Q ApiEcPoint `json:"q"`
}

type ApiClientPreSign struct {
	EncKey         []byte             `json:"enc_key"`
	M              big.Int            `json:"m"`
	R              ApiEcPoint         `json:"r"`
	Pi             ApiDLogProof       `json:"pi"`
	PailliarPubKey paillier.PublicKey `json:"pailliar_pub_key"`
}
