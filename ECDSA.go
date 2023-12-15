package ECDSA

import (
	"ECwrap"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha512"
	"errors"
	"fmt"
	"math/big"
)

type PubKey struct {
	Order *big.Int        // Order of the underlying field (for point operations like addition, doubling)
	N     *big.Int        // Order of the base point (for key operations)
	Pb    *ECwrap.ECPoint // base point
	Q     *ECwrap.ECPoint // public key point
}

type PrivKey struct {
	Pub PubKey
	d   *big.Int
}

type Signature struct {
	s, r *big.Int
}

func OutKey(key *PrivKey) {
	fmt.Printf("Privatekey: %s\nPublickey:", key.d)
	ECwrap.Out(key.Pub.Q)
	fmt.Print("\n")
}

func Hash(s string) []byte {
	h := sha512.New()
	h.Write([]byte(s))
	return h.Sum(nil)
}

func KeyGen(curve elliptic.Curve) (*PrivKey, error) {
	Priv := new(PrivKey)
	Priv.Pub.Order = new(big.Int).Set(curve.Params().P)
	Priv.Pub.N = new(big.Int).Set(curve.Params().N)
	Priv.Pub.Pb = new(ECwrap.ECPoint)
	Priv.Pub.Pb.SetCoords(curve.Params().Gx, curve.Params().Gy, big.NewInt(1))

	var err error
	Priv.d, err = rand.Int(rand.Reader, new(big.Int).Sub(Priv.Pub.N, big.NewInt(1)))
	if err != nil {
		return nil, errors.New("error generating rand int")
	}

	Priv.Pub.Q = ECwrap.ScalarMul(Priv.Pub.Pb, Priv.d, Priv.Pub.Order)
	Priv.Pub.Q.ECPNormalize(Priv.Pub.Order)

	Pcheck := ECwrap.ScalarMul(Priv.Pub.Q, Priv.Pub.N, Priv.Pub.Order)
	if Priv.Pub.Q.Z.Sign() == 0 ||
		Pcheck.Z.Sign() != 0 ||
		!Priv.Pub.Q.IsOnCurve(curve) {
		return nil, errors.New("error generating key-pair")
	}

	return Priv, nil
}

func (Priv *PrivKey) Sign(hash []byte) *Signature {
	h := new(big.Int).SetBytes(hash)
	N_l := Priv.Pub.N.BitLen()
	h_l := h.BitLen()
	z := new(big.Int).Rsh(
		h,
		uint(h_l-N_l),
	)
	//fmt.Printf("h=%s\nN_l=%d\nh_l=%d\nz=%s\nz_l=%d\nz_shift_l=%d\n", h, N_l, h_l, z, z.BitLen(), uint(h_l-N_l))

	k, _ := rand.Int(rand.Reader, new(big.Int).Sub(Priv.Pub.N, big.NewInt(1)))

	P1 := ECwrap.ScalarMul(Priv.Pub.Pb, k, Priv.Pub.Order)
	P1.ECPNormalize(Priv.Pub.Order)

	sig := new(Signature)
	sig.r = new(big.Int).Mod(P1.X, Priv.Pub.N)
	if sig.r.Sign() == 0 {
		// negligible chance, so dont care
		return Priv.Sign(hash)
	}
	sig.s = new(big.Int).Mod(
		new(big.Int).Mul(
			new(big.Int).ModInverse(
				k, Priv.Pub.N,
			),
			new(big.Int).Add(
				z,
				new(big.Int).Mul(Priv.d, sig.r),
			),
		),
		Priv.Pub.N,
	)
	if sig.r.Sign() == 0 {
		// negligible chance, so dont care
		return Priv.Sign(hash)
	}

	return sig
}

func (Pub *PubKey) Verify(sig *Signature, hash []byte) bool {
	r := new(big.Int).Set(sig.r)
	s := new(big.Int).Set(sig.s)

	h := new(big.Int).SetBytes(hash)
	N_l := Pub.N.BitLen()
	h_l := h.BitLen()
	z := new(big.Int).Rsh(
		h,
		uint(h_l-N_l),
	)

	c := new(big.Int).ModInverse(s, Pub.N)
	u1 := new(big.Int).Mod(
		new(big.Int).Mul(
			z, c,
		),
		Pub.N,
	)
	u2 := new(big.Int).Mod(
		new(big.Int).Mul(
			r, c,
		),
		Pub.N,
	)
	P1 := ECwrap.ScalarMul(Pub.Pb, u1, Pub.Order)
	P2 := ECwrap.ScalarMul(Pub.Q, u2, Pub.Order)
	P0 := ECwrap.AddJacobian(P1, P2, Pub.Order)
	P0.ECPNormalize(Pub.Order)
	x0 := new(big.Int).Mod(P0.X, Pub.N)

	return x0.Cmp(r) == 0
}
