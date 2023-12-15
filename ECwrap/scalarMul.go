package ECwrap

import "math/big"

// Multiplies point by a given constant
// Uses Montgomery ladder algorithm,
// but uses it badly... The result is
// different from expected multiplication
// result. It should be Ok for Point generaion tho
func ScalarMulML(P *ECPoint, num, Order *big.Int) *ECPoint {
	P0 := new(ECPoint)
	P0.SetCoords(big.NewInt(0), big.NewInt(0), big.NewInt(0)) // point at infinity
	P1 := new(ECPoint)
	P1.SetCoords(P.X, P.Y, P.Z)
	n := new(big.Int).Set(num)
	//n := big.NewInt(32)
	var sign int
	for n.Sign() > 0 {
		bit := new(big.Int).And(n, big.NewInt(1))
		sign = bit.Sign() // we only need to know if bit is 0 or 1
		if sign == 0 {
			P1 = AddJacobian(P0, P1, Order)
			P0 = DoubleJacobian(P0, Order)
		} else if sign == 1 {
			P0 = AddJacobian(P0, P1, Order)
			P1 = DoubleJacobian(P1, Order)
		}
		// fmt.Print("\n")
		// fmt.Printf("sign %d\n", sign)
		// Out(P0)
		// Out(P1)
		// fmt.Print("\n")
		n.Rsh(n, 1)
	}
	if sign > 0 {
		return P0
	} else {
		return P1
	}
}

func ScalarMul(P *ECPoint, num, Order *big.Int) *ECPoint {
	P0 := new(ECPoint)
	P0.SetCoords(big.NewInt(0), big.NewInt(0), big.NewInt(0)) // point at infinity
	P1 := new(ECPoint)
	P1.SetCoords(P.X, P.Y, P.Z)

	n := new(big.Int).Set(num)
	//n := big.NewInt(32)
	for n.Sign() > 0 {
		bit := new(big.Int).And(n, big.NewInt(1))
		sign := bit.Sign()

		if sign == 1 {
			P0 = AddJacobian(P0, P1, Order)
		}
		P1 = DoubleJacobian(P1, Order)

		n.Rsh(n, 1)
	}
	return P0
}
