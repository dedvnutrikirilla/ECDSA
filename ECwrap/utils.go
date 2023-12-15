package ECwrap

import (
	"crypto/elliptic"
	"crypto/rand"
	"errors"
	"fmt"
	"math/big"
)

// Represents coordinates of a point on
// elliptic curve
//
// If Z = 1, point is in affine form
// otherways, in jacobian. Third coordinate
// in jacobian form allows avoid inversion
// operations, which speeds up calculation
type ECPoint struct {
	X *big.Int
	Y *big.Int

	// Z for Jacobian points
	// If Z = 1, X and Y are same as if point was affine
	Z *big.Int
}

func Out(P *ECPoint) {
	fmt.Printf("P (x, y, z):\n(x : %s\ny : %s\nz : %s)\n", P.X, P.Y, P.Z)
}

// Returns new ECPoint, and sets coordinates
// to provided string values. Sets Z to 1.
// You can set different values for `base`
func SetPointStr(x, y string, base int) (*ECPoint, error) {
	P := new(ECPoint)
	var isX, isY bool
	P.X, isX = new(big.Int).SetString(x, base)
	if !isX {
		return nil, errors.New("cannot cast x string")
	}
	P.Y, isY = new(big.Int).SetString(y, base)
	if !isY {
		return nil, errors.New("cannot cast y string")
	}

	P.Z = big.NewInt(1)
	return P, nil
}

// Returns new ECPoint, and sets coordinates
// to provided string values.
// You can set different values for `base`
func SetPointJacobianStr(x, y, z string, base int) (*ECPoint, error) {
	P := new(ECPoint)
	var isX, isY, isZ bool

	P.X, isX = new(big.Int).SetString(x, base)
	if !isX {
		return nil, errors.New("cannot cast x string")
	}
	P.Y, isY = new(big.Int).SetString(y, base)
	if !isY {
		return nil, errors.New("cannot cast y string")
	}
	P.Z, isZ = new(big.Int).SetString(z, base)
	if !isZ {
		return nil, errors.New("cannot cast z string")
	}

	return P, nil
}

func (P *ECPoint) SetCoords(x, y, z *big.Int) {
	P.X = new(big.Int).Set(x)
	P.Y = new(big.Int).Set(y)
	P.Z = new(big.Int).Set(z)
}

// Casts Jacobian point to Affine, setting
// Z = 1. Uses inversion, which badly
// affects performance. If recieves point
// at infinity with Z != 0, behaivior is unpredicted
func (P *ECPoint) ECPNormalize(Order *big.Int) {
	if P.Z.Sign() == 0 {
		// could not normalize point at infinity
		return
	}
	Zinv := new(big.Int).ModInverse(P.Z, Order)
	ZZinv := new(big.Int).Mul(Zinv, Zinv)
	ZZZinv := new(big.Int).Mul(ZZinv, Zinv)
	// ZZZрада?
	P.X = new(big.Int).Mod(new(big.Int).Mul(P.X, ZZinv), Order)
	P.Y = new(big.Int).Mod(new(big.Int).Mul(P.Y, ZZZinv), Order)
	P.Z = big.NewInt(1)
}

// Returns boolean saying if point is on the
// specified curve. If point is Jacobian, function
// normalizes its copy, not the original
func (P *ECPoint) IsOnCurve(curve elliptic.Curve) bool {
	if P.Z.Cmp(big.NewInt(1)) != 0 {
		temp := new(ECPoint)
		temp.SetCoords(P.X, P.Y, P.Z)
		temp.ECPNormalize(curve.Params().P)
		return curve.IsOnCurve(temp.X, temp.Y)
	}
	return curve.IsOnCurve(P.X, P.Y)
}

func OutIsOnCurve(P *ECPoint, curve elliptic.Curve) {
	fmt.Printf("is on curve: %t\n", P.IsOnCurve(curve))
}

func RandPoint(curve elliptic.Curve) (*ECPoint, error) {
	n, err := rand.Int(rand.Reader, curve.Params().P)
	if err != nil {
		return nil, errors.New("could not generate rand value")
	}
	G := new(ECPoint)
	G.SetCoords(curve.Params().Gx, curve.Params().Gy, big.NewInt(1))
	P := ScalarMul(G, n, curve.Params().P)
	return P, err
}
