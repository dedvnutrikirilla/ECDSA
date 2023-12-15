package ECwrap

import (
	"math/big"
)

// This function was designed for learning purposes and
// is not advised for real life cryptographic use
//
// The whole wrapper is based arround go `crypto/elliptic`
// package which is now deprecated btw. In this package
// constant `a` is not specified in any of the params
// so using usual formulas is difficult
//
// The "dbl-2001-b" doubling formula is used instead
// https://hyperelliptic.org/EFD/g1p/auto-shortw-jacobian-3.html#doubling-dbl-2001-b
// It works on jacobian coordinates assuming that a4 = -3
// for short Weirstrass curves
func DoubleJacobian(P *ECPoint, Order *big.Int) *ECPoint {
	D := new(ECPoint)

	if P.Y.Sign() == 0 {
		// Point at infinity
		D.SetCoords(P.X, P.Y, P.Z)
		return D
	}

	delta := new(big.Int).Mul(P.Z, P.Z)
	gamma := new(big.Int).Mul(P.Y, P.Y)
	beta := new(big.Int).Mul(P.X, gamma)
	//	alpha = 3*(X1-delta)*(X1+delta)
	alpha := new(big.Int).Mul(
		big.NewInt(3),
		new(big.Int).Mul(
			new(big.Int).Sub(
				P.X,
				delta,
			),
			new(big.Int).Add(
				P.X,
				delta,
			),
		),
	)

	//	X3 = alpha2-8*beta
	D.X = new(big.Int).Mod(
		new(big.Int).Sub(
			new(big.Int).Mul(alpha, alpha),
			new(big.Int).Mul(
				big.NewInt(8),
				beta,
			),
		),
		Order,
	)

	//	Z3 = (Y1+Z1)^(2)-gamma-delta
	YZ := new(big.Int).Add(P.Y, P.Z)
	D.Z = new(big.Int).Mod(
		new(big.Int).Sub(
			new(big.Int).Sub(
				new(big.Int).Mul(YZ, YZ),
				gamma,
			),
			delta,
		),
		Order,
	)

	//	Y3 = alpha*(4*beta-X3)-8*gamma^(2)
	D.Y = new(big.Int).Mod(
		new(big.Int).Sub(
			new(big.Int).Mul(
				alpha,
				new(big.Int).Sub(
					new(big.Int).Mul(
						big.NewInt(4),
						beta,
					),
					D.X,
				),
			),
			new(big.Int).Mul(
				big.NewInt(8),
				new(big.Int).Mul(gamma, gamma),
			),
		),
		Order,
	)

	return D
}

// This function was designed for learning purposes and
// is not advised for real life cryptographic use
//
// Function is untested, should work as expected, though.
// If ya have as braindead moment as I had while writing
// this function you re free to try it.
// Remember that `crypto/elliptic` package is now deprecated,
// so any changes in it may not be written in its docs
// Double check the value you set as `a`, cause curve
// description may not match its parameters
func DoubleWithA(P *ECPoint, Order, A *big.Int) *ECPoint {
	D := new(ECPoint)

	// s = (3*X^(2) + a) / (2*Y)
	// s = (3*X^(2) + a) * (2*Y)^(-1)
	S := new(big.Int).Mul(
		new(big.Int).Add(
			new(big.Int).Mul(
				big.NewInt(3),
				new(big.Int).Mul(P.X, P.X),
			),
			A,
		),
		new(big.Int).ModInverse(
			new(big.Int).Mul(big.NewInt(2), P.Y),
			Order,
		),
	)

	// X' = S^(2) - 2*X
	D.X = new(big.Int).Mod(
		new(big.Int).Sub(
			new(big.Int).Mul(S, S),
			new(big.Int).Mul(big.NewInt(2), P.X),
		),
		Order,
	)

	// Y' = S*(X-X') - Y
	D.Y = new(big.Int).Mod(
		new(big.Int).Sub(
			new(big.Int).Mul(
				S,
				new(big.Int).Sub(P.X, D.X),
			),
			P.Y,
		),
		Order,
	)

	D.Z = big.NewInt(1)

	return D
}

// This function was designed for learning purposes and
// is not advised for real life cryptographic use
//
// Function is untested, should work as expected, though.
// If ya have as braindead moment as I had while writing
// this function you re free to try it.
// Remember that `crypto/elliptic` package is now deprecated,
// so any changes in it may not be written in its docs
// Double check the value you set as `a`, cause curve
// description may not match its parameters
func DoubleJacobianWithA(P *ECPoint, Order, A *big.Int) *ECPoint {
	D := new(ECPoint)

	if P.Y.Sign() == 0 {
		// Point at infinity
		D.SetCoords(P.X, P.Y, P.Z)
		return D
	}

	YY := new(big.Int).Mul(P.Y, P.Y)
	// S = 4*X*Y^(2)
	S := new(big.Int).Mul(
		big.NewInt(4),
		new(big.Int).Mul(
			P.X,
			YY,
		),
	)
	ZZ := new(big.Int).Mul(P.Z, P.Z)
	// M = 3*X^(2) + a*Z^(4)
	M := new(big.Int).Add(
		new(big.Int).Mul(
			big.NewInt(3),
			new(big.Int).Mul(P.X, P.X),
		),
		new(big.Int).Mul(
			A,
			new(big.Int).Mul(
				ZZ,
				ZZ,
			),
		),
	)
	// X' = M^(2) - 2*S
	D.X = new(big.Int).Mod(
		new(big.Int).Sub(
			new(big.Int).Mul(M, M),
			new(big.Int).Mul(
				big.NewInt(2),
				S,
			),
		),
		Order,
	)
	// Y' = M*(S - X') - 8*Y^(4)
	D.Y = new(big.Int).Mod(
		new(big.Int).Sub(
			new(big.Int).Mul(
				M,
				new(big.Int).Sub(S, D.X),
			),
			new(big.Int).Mul(
				big.NewInt(8),
				new(big.Int).Mul(YY, YY),
			),
		),
		Order,
	)

	// Z' = 2*Y*Z
	D.Z = new(big.Int).Mod(
		new(big.Int).Mul(
			big.NewInt(2),
			new(big.Int).Mul(P.Y, P.Z),
		),
		Order,
	)

	// return (X', Y', Z')
	return D
}
