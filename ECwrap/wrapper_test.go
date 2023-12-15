package ECwrap

import (
	"crypto/elliptic"
	"crypto/rand"
	"fmt"
	"math/big"
	"testing"
)

// curve on which we will test the package
var curve = elliptic.P256()

// order of the underlying field
var Order = curve.Params().P

func isOnCurveNormal(x, y *big.Int) bool {
	return curve.IsOnCurve(x, y)
}

func randPointNormal() *ECPoint {
	P := new(ECPoint)
	P.Z = big.NewInt(1)
	_, P.X, P.Y, _ = elliptic.GenerateKey(curve, rand.Reader)
	return P
}

// Testing function that returns a ECPoint, which
// is NOT on curve, with crypto/elliptic
// designed only for testing purposes
func randPointWrong() *ECPoint {
	P := randPointNormal()
	n, _ := rand.Int(rand.Reader, Order)
	for isOnCurveNormal(P.X, P.Y) {
		P.X.Mod(new(big.Int).Mul(P.X, n), Order) // damage point coords
	}
	return P
}

func TestRandPoint(t *testing.T) {
	P, error := RandPoint(curve)
	if error != nil {
		t.Fatalf(`RandPoint() point generation error: %v`, error)
	}
	P.ECPNormalize(Order)
	want := true
	// test on built-in function
	check := isOnCurveNormal(P.X, P.Y)
	if want != check {
		t.Fatalf(`RandPoint() is on curve check = %t, expected = %t`, check, want)
	}
}
func TestIsOnCurveTrue(t *testing.T) {
	P := randPointNormal()
	res := P.IsOnCurve(curve)
	want := true
	if want != res {
		t.Fatalf(`IsOnCurve(~OK point~) result = %t, expected = %t`, res, want)
	}
}
func TestIsOnCurveTrue2(t *testing.T) {
	P, _ := RandPoint(curve)
	res := P.IsOnCurve(curve)
	want := true
	if want != res {
		t.Fatalf(`IsOnCurve(~OK point~) result = %t, expected = %t`, res, want)
	}
}
func TestIsOnCurveJacobianTrue(t *testing.T) {
	P := randPointNormal()
	// scalar mult to have modified Z != 1
	if P.Z.Cmp(big.NewInt(1)) == 0 {
		P = ScalarMul(P, big.NewInt(64), Order)
	}
	res := P.IsOnCurve(curve)
	want := true
	if want != res {
		t.Fatalf(`IsOnCurve(~OK Jacobian point~) result = %t, expected = %t`, res, want)
	}
}
func TestIsOnCurveFalse(t *testing.T) {
	P := randPointWrong()
	res := P.IsOnCurve(curve)
	want := false
	if want != res {
		t.Fatalf(`IsOnCurve(~Wrong point~) result = %t, expected = %t`, res, want)
	}
}
func TestScalarMul(t *testing.T) {
	P := randPointNormal()
	n, _ := rand.Int(rand.Reader, Order)

	Pm := ScalarMul(P, n, Order)
	valid := Pm.IsOnCurve(curve)
	if !valid {
		t.Fatalf(`ScalarMul() is on curve = %t, expected = %t`, valid, true)
	}
	Pm.ECPNormalize(Order)

	// calculate scalar multiplication with built-in functions
	Pmn := new(ECPoint)
	Pmn.Z = big.NewInt(1)
	Pmn.X, Pmn.Y = curve.ScalarMult(P.X, P.Y, n.Bytes())
	if Pm.X.Cmp(Pmn.X) != 0 ||
		Pm.Y.Cmp(Pmn.Y) != 0 ||
		Pm.Z.Cmp(Pmn.Z) != 0 {
		t.Logf(`ScalarMul() x = %s; expected = %s`, Pm.X, Pmn.X)
		t.Logf(`ScalarMul() y = %s; expected = %s`, Pm.Y, Pmn.Y)
		t.Logf(`ScalarMul() z = %s; expected = %s`, Pm.Z, Pmn.Z)
		t.FailNow()
	}
}

func TestScalarMul2(t *testing.T) {
	P := randPointNormal()
	//n := new(big.Int).Sub(curve.Params().P, big.NewInt(1))
	n := curve.Params().P

	Pm := ScalarMul(P, n, Order)
	valid := Pm.IsOnCurve(curve)
	if !valid {
		t.Fatalf(`ScalarMul() is on curve = %t, expected = %t`, valid, true)
	}
	Pm.ECPNormalize(Order)

	// calculate scalar multiplication with built-in functions
	Pmn := new(ECPoint)
	Pmn.Z = big.NewInt(1)
	Pmn.X, Pmn.Y = curve.ScalarMult(P.X, P.Y, n.Bytes())
	if Pm.X.Cmp(Pmn.X) != 0 ||
		Pm.Y.Cmp(Pmn.Y) != 0 ||
		Pm.Z.Cmp(Pmn.Z) != 0 {
		t.Logf(`ScalarMul() x = %s; expected = %s`, Pm.X, Pmn.X)
		t.Logf(`ScalarMul() y = %s; expected = %s`, Pm.Y, Pmn.Y)
		t.Logf(`ScalarMul() z = %s; expected = %s`, Pm.Z, Pmn.Z)
		t.FailNow()
	}
	fmt.Printf("ScalarMul() x = %s; expected = %s, P.X = %s\n", Pm.X, Pmn.X, P.X)
	fmt.Printf("ScalarMul() y = %s; expected = %s, P.Y = %s\n", Pm.Y, Pmn.Y, P.Y)
	fmt.Printf("ScalarMul() z = %s; expected = %s, P.Z = %s\n", Pm.Z, Pmn.Z, P.Z)
}

/*
	func TestScalarMulML(t *testing.T) {
		// Function uses `ScalarMulML` a bad implementation of
		// Montgomary Ladder which returns a valid point,
		// but with coordinates that do not match expected ones

		P := randPointNormal()
		n, _ := rand.Int(rand.Reader, Order)

		Pm := ScalarMulML(P, n, Order)
		valid := Pm.IsOnCurve(curve)
		if !valid {
			t.Fatalf(`ScalarMul() is on curve = %t, expected = %t`, valid, true)
		}
		Pm.ECPNormalize(Order)

		// calculate scalar multiplication with built-in functions
		Pmn := new(ECPoint)
		Pmn.Z = big.NewInt(1)
		Pmn.X, Pmn.Y = curve.ScalarMult(P.X, P.Y, n.Bytes())
		if Pm.X.Cmp(Pmn.X) != 0 ||
			Pm.Y.Cmp(Pmn.Y) != 0 ||
			Pm.Z.Cmp(Pmn.Z) != 0 {
			t.Logf(`ScalarMul() x = %s; expected = %s`, Pm.X, Pmn.X)
			t.Logf(`ScalarMul() y = %s; expected = %s`, Pm.Y, Pmn.Y)
			t.Logf(`ScalarMul() z = %s; expected = %s`, Pm.Z, Pmn.Z)
			t.FailNow()
		}
	}
*/
func TestAddGeneric(t *testing.T) {
	P1, _ := RandPoint(curve)
	P2, _ := RandPoint(curve)
	// revert points to affine
	P1.ECPNormalize(Order)
	P2.ECPNormalize(Order)
	//
	P3, err := AddGeneric(P1, P2, Order)
	if err != nil {
		t.Fatalf(`AddGeneric() error = %v, expected = %v`, err, nil)
	}
	valid := P3.IsOnCurve(curve)
	if !valid {
		t.Fatalf(`AddGeneric() is on curve = %t, expected = %t`, valid, true)
	}

	//compare to normal addition results
	P3n := new(ECPoint)
	P3n.Z = big.NewInt(1)
	P3n.X, P3n.Y = curve.Add(P1.X, P1.Y, P2.X, P2.Y)

	if P3.X.Cmp(P3n.X) != 0 ||
		P3.Y.Cmp(P3n.Y) != 0 ||
		P3.Z.Cmp(P3n.Z) != 0 {
		t.Logf(`AddGeneric() x = %s; expected = %s`, P3.X, P3n.X)
		t.Logf(`AddGeneric() y = %s; expected = %s`, P3.Y, P3n.Y)
		t.Logf(`AddGeneric() z = %s; expected = %s`, P3.Z, P3n.Z)
		t.FailNow()
	}
}
func TestAddJacobianZeqZ(t *testing.T) {
	P1, _ := RandPoint(curve)
	P2, _ := RandPoint(curve)
	// revert points to affine
	P1.ECPNormalize(Order)
	P2.ECPNormalize(Order)
	//
	P3 := AddJacobianZeqZ(P1, P2, Order)

	valid := P3.IsOnCurve(curve)
	if !valid {
		t.Fatalf(`AddJacobianZeqZ() is on curve = %t, expected = %t`, valid, true)
	}

	//compare to normal addition results
	P3n := new(ECPoint)
	P3n.Z = big.NewInt(1)
	P3n.X, P3n.Y = curve.Add(P1.X, P1.Y, P2.X, P2.Y)

	P3.ECPNormalize(Order)
	if P3.X.Cmp(P3n.X) != 0 ||
		P3.Y.Cmp(P3n.Y) != 0 ||
		P3.Z.Cmp(P3n.Z) != 0 {
		t.Logf(`AddJacobianZeqZ() x = %s; expected = %s`, P3.X, P3n.X)
		t.Logf(`AddJacobianZeqZ() y = %s; expected = %s`, P3.Y, P3n.Y)
		t.Logf(`AddJacobianZeqZ() z = %s; expected = %s`, P3.Z, P3n.Z)
		t.FailNow()
	}
}
func TestAddJacobianZeqZeq1(t *testing.T) {
	P1, _ := RandPoint(curve)
	P2, _ := RandPoint(curve)
	// revert points to affine
	P1.ECPNormalize(Order)
	P2.ECPNormalize(Order)
	//
	P3 := AddJacobianZeqZeq1(P1, P2, Order)
	P3.ECPNormalize(Order)
	valid := P3.IsOnCurve(curve)
	if !valid {
		t.Fatalf(`AddJacobianZeqZeq1() is on curve = %t, expected = %t`, valid, true)
	}

	//compare to normal addition results
	P3n := new(ECPoint)
	P3n.Z = big.NewInt(1)
	P3n.X, P3n.Y = curve.Add(P1.X, P1.Y, P2.X, P2.Y)

	if P3.X.Cmp(P3n.X) != 0 ||
		P3.Y.Cmp(P3n.Y) != 0 ||
		P3.Z.Cmp(P3n.Z) != 0 {
		t.Logf(`AddJacobianZeqZeq1() x = %s; expected = %s`, P3.X, P3n.X)
		t.Logf(`AddJacobianZeqZeq1() y = %s; expected = %s`, P3.Y, P3n.Y)
		t.Logf(`AddJacobianZeqZeq1() z = %s; expected = %s`, P3.Z, P3n.Z)
		t.FailNow()
	}
}
func TestAddJacobianWithZeqZeq1(t *testing.T) {
	P1, _ := RandPoint(curve)
	P2, _ := RandPoint(curve)
	// revert points to affine
	P1.ECPNormalize(Order)
	P2.ECPNormalize(Order)
	//
	P3 := AddJacobian(P1, P2, Order)
	P3.ECPNormalize(Order)
	valid := P3.IsOnCurve(curve)
	if !valid {
		t.Fatalf(`AddJacobian() is on curve = %t, expected = %t`, valid, true)
	}

	//compare to normal addition results
	P3n := new(ECPoint)
	P3n.Z = big.NewInt(1)
	P3n.X, P3n.Y = curve.Add(P1.X, P1.Y, P2.X, P2.Y)

	if P3.X.Cmp(P3n.X) != 0 ||
		P3.Y.Cmp(P3n.Y) != 0 ||
		P3.Z.Cmp(P3n.Z) != 0 {
		t.Logf(`AddJacobian({x1, y1, 1}, {x2, y2, 1}) x = %s; expected = %s`, P3.X, P3n.X)
		t.Logf(`AddJacobian({x1, y1, 1}, {x2, y2, 1}) y = %s; expected = %s`, P3.Y, P3n.Y)
		t.Logf(`AddJacobian({x1, y1, 1}, {x2, y2, 1}) z = %s; expected = %s`, P3.Z, P3n.Z)
		t.FailNow()
	}
}
func TestAddJacobian(t *testing.T) {
	P1, _ := RandPoint(curve)
	P2, _ := RandPoint(curve)
	// Ensure points with z1 != z2 != 1
	for P1.Z.Cmp(big.NewInt(1)) == 0 ||
		P2.Z.Cmp(big.NewInt(1)) == 0 ||
		P1.Z.Cmp(P2.Z) == 0 {
		P1 = ScalarMul(P1, big.NewInt(65), Order)
		P2 = ScalarMul(P2, big.NewInt(65), Order)
	}
	P3 := AddJacobian(P1, P2, Order)
	P3.ECPNormalize(Order)
	valid := P3.IsOnCurve(curve)
	if !valid {
		t.Fatalf(`AddJacobian() is on curve = %t, expected = %t`, valid, true)
	}

	// compare to normal addition results
	P3n := new(ECPoint)
	P3n.Z = big.NewInt(1)
	// revert points to affine
	P1.ECPNormalize(Order)
	P2.ECPNormalize(Order)
	//
	P3n.X, P3n.Y = curve.Add(P1.X, P1.Y, P2.X, P2.Y)

	if P3.X.Cmp(P3n.X) != 0 ||
		P3.Y.Cmp(P3n.Y) != 0 ||
		P3.Z.Cmp(P3n.Z) != 0 {
		t.Logf(`AddJacobian({x1, y1, 1}, {x2, y2, 1}) x = %s; expected = %s`, P3.X, P3n.X)
		t.Logf(`AddJacobian({x1, y1, 1}, {x2, y2, 1}) y = %s; expected = %s`, P3.Y, P3n.Y)
		t.Logf(`AddJacobian({x1, y1, 1}, {x2, y2, 1}) z = %s; expected = %s`, P3.Z, P3n.Z)
		t.FailNow()
	}
}

// For p256
func TestSetString(t *testing.T) {
	// For p256
	P1, err := SetPointJacobianStr(
		"33902140775765101738410685059987019342010528636018478397152239172344793403990",
		"90554104345946232443294503290205999523006922980121305755113287951440061705917",
		"1",
		10,
	)

	valid := P1.IsOnCurve(curve)
	if !valid || err != nil {
		t.Fatalf(`SetPointJacobianStr() is on curve = %t, error = %v; expected is on curve = %t, err = %v`,
			valid, err, true, nil)
	}
}
