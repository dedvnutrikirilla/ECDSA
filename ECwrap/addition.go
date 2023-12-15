package ECwrap

import (
	"errors"
	"math/big"
)

// This function was designed for learning purposes and
// is not advised for real life cryptographic use
//
// Function works on Affine coordinates. It is recomended
// to switch to operating on Jacobian coordinates, as they
// have no inversions (cost for field inversions is
// significantly higher than for multiplications)
// If you need your code to run faster use more
// specific implementations, or more refined packages
//
// If any of the points is the point at infinity
// behavior is unpredicted
func AddGeneric(P1, P2 *ECPoint, Order *big.Int) (*ECPoint, error) {
	if P1.X.Cmp(P2.X) == 0 {
		return nil, errors.New("points are mutual inverse (x1 == x2)")
	}

	P3 := new(ECPoint)

	Slope := new(big.Int).Mul(
		new(big.Int).Sub(P2.Y, P1.Y),
		new(big.Int).ModInverse(
			new(big.Int).Sub(P2.X, P1.X),
			Order,
		),
	)

	P3.X = new(big.Int).Mod(
		new(big.Int).Sub(
			new(big.Int).Sub(
				new(big.Int).Mul(Slope, Slope),
				P1.X,
			),
			P2.X,
		),
		Order,
	)

	P3.Y = new(big.Int).Mod(
		new(big.Int).Sub(
			new(big.Int).Mul(
				new(big.Int).Sub(
					P1.X,
					P3.X,
				),
				Slope,
			),
			P1.Y,
		),
		Order,
	)

	P3.Z = big.NewInt(1)
	return P3, nil
}

// This function was designed for learning purposes and
// is not advised for real life cryptographic use
//
// Function works on jacobian coordinates, assuming
// that Z1 != Z2
//
// Function is able to handle operations with points on
// infinity (used in scalar multiplication). But if
// point at infinity has Z != 0, behaivor is unpredicted
func AddJacobian(P1, P2 *ECPoint, Order *big.Int) *ECPoint {
	P3 := new(ECPoint)
	if P1.Z.Sign() == 0 {
		// P1 is a point at infinity
		P3.SetCoords(P2.X, P2.Y, P2.Z)
		return P3
	} else if P2.Z.Sign() == 0 {
		// P2 is a point at infinity
		P3.SetCoords(P1.X, P1.Y, P1.Z)
		return P3
	}

	// calculate mid-values
	U1 := new(big.Int).Mul(new(big.Int).Mul(P2.Z, P2.Z), P1.X)
	U2 := new(big.Int).Mul(new(big.Int).Mul(P1.Z, P1.Z), P2.X)
	S1 := new(big.Int).Mul(new(big.Int).Mul(new(big.Int).Mul(P2.Z, P2.Z), P2.Z), P1.Y)
	S2 := new(big.Int).Mul(new(big.Int).Mul(new(big.Int).Mul(P1.Z, P1.Z), P1.Z), P2.Y)

	if U1.Cmp(U2) == 0 {
		if S1.Cmp(S2) != 0 {
			// one of the points is a point at infinity, but it wasn't
			// tracked in the begginning of the function. This is abnormal
			P3.SetCoords(big.NewInt(0), big.NewInt(0), big.NewInt(0))
			return P3
		} else {
			return DoubleJacobian(P1, Order)
		}
	}

	H := new(big.Int).Sub(U2, U1)
	R := new(big.Int).Sub(S2, S1)
	HH := new(big.Int).Mul(H, H)
	HHH := new(big.Int).Mul(HH, H)

	P3.X = new(big.Int).Mod(
		new(big.Int).Sub(
			new(big.Int).Sub(
				new(big.Int).Mul(R, R),
				HHH,
			),
			new(big.Int).Mul(
				big.NewInt(2),
				new(big.Int).Mul(
					U1,
					HH,
				),
			),
		),
		Order,
	)

	P3.Y = new(big.Int).Mod(
		new(big.Int).Sub(
			new(big.Int).Mul(
				R,
				new(big.Int).Sub(
					new(big.Int).Mul(
						U1,
						HH,
					),
					P3.X,
				),
			),
			new(big.Int).Mul(
				S1,
				HHH,
			),
		),
		Order,
	)

	P3.Z = new(big.Int).Mod(
		new(big.Int).Mul(
			new(big.Int).Mul(
				P1.Z,
				P2.Z,
			),
			H,
		),
		Order,
	)

	return P3
}

// This function was designed for learning purposes and
// is not advised for real life cryptographic use
//
// Function works on jacobian coordinates, assuming
// that Z1 == Z2, allowing to simplify the furmula.
// performs less calculations than `AddJacobian`
//
// Probably, formula used should be further refined,
// as for now it simplifies only calculations before
// X, Y, Z calculations
func AddJacobianZeqZ(P1, P2 *ECPoint, Order *big.Int) *ECPoint {
	P3 := new(ECPoint)
	if P1.Z.Sign() == 0 {
		// P1 is a point at infinity
		P3.SetCoords(P2.X, P2.Y, P2.Z)
		return P3
	} else if P2.Z.Sign() == 0 {
		// P2 is a point at infinity
		P3.SetCoords(P1.X, P1.Y, P1.Z)
		return P3
	}
	//	P1.Z == P2.Z
	ZZ := new(big.Int).Mul(P1.Z, P2.Z)
	ZZZ := new(big.Int).Mul(P1.Z, ZZ)
	U1 := new(big.Int).Mul(P1.X, ZZ)
	U2 := new(big.Int).Mul(P2.X, ZZ)
	S1 := new(big.Int).Mul(P1.Y, ZZZ)
	S2 := new(big.Int).Mul(P2.Y, ZZZ)

	H := new(big.Int).Sub(U2, U1)
	R := new(big.Int).Sub(S2, S1)

	HH := new(big.Int).Mul(H, H)
	HHH := new(big.Int).Mul(HH, H)

	P3.X = new(big.Int).Mod(
		new(big.Int).Sub(
			new(big.Int).Sub(
				new(big.Int).Mul(R, R),
				HHH,
			),
			new(big.Int).Mul(
				big.NewInt(2),
				new(big.Int).Mul(
					U1,
					HH,
				),
			),
		),
		Order,
	)

	P3.Y = new(big.Int).Mod(
		new(big.Int).Sub(
			new(big.Int).Mul(
				R,
				new(big.Int).Sub(
					new(big.Int).Mul(
						U1,
						HH,
					),
					P3.X,
				),
			),
			new(big.Int).Mul(
				S1,
				HHH,
			),
		),
		Order,
	)

	P3.Z = new(big.Int).Mod(
		new(big.Int).Mul(H, P1.Z),
		Order,
	)

	return P3
}

// This function was designed for learning purposes and
// is not advised for real life cryptographic use
//
// Function works on jacobian coordinates, assuming
// that Z1 == Z2 == 1, allowing to simplify the furmula.
// performs less calculations than `AddJacobianZeqZ`
func AddJacobianZeqZeq1(P1, P2 *ECPoint, Order *big.Int) *ECPoint {
	P3 := new(ECPoint)
	if P1.Z.Sign() == 0 {
		// P1 is a point at infinity
		P3.SetCoords(P2.X, P2.Y, P2.Z)
		return P3
	} else if P2.Z.Sign() == 0 {
		// P2 is a point at infinity
		P3.SetCoords(P1.X, P1.Y, P1.Z)
		return P3
	}
	//	P1.Z == P2.Z == 1
	H := new(big.Int).Sub(P2.X, P1.X)
	R := new(big.Int).Sub(P2.Y, P1.Y)

	HH := new(big.Int).Mul(H, H)
	HHH := new(big.Int).Mul(HH, H)

	P3.X = new(big.Int).Mod(
		new(big.Int).Sub(
			new(big.Int).Sub(
				new(big.Int).Mul(R, R),
				HHH,
			),
			new(big.Int).Mul(
				big.NewInt(2),
				new(big.Int).Mul(
					P1.X,
					HH,
				),
			),
		),
		Order,
	)

	P3.Y = new(big.Int).Mod(
		new(big.Int).Sub(
			new(big.Int).Mul(
				R,
				new(big.Int).Sub(
					new(big.Int).Mul(
						P1.X,
						HH,
					),
					P3.X,
				),
			),
			new(big.Int).Mul(
				P1.Y,
				HHH,
			),
		),
		Order,
	)

	P3.Z = new(big.Int).Mod(H, Order)

	return P3
}
