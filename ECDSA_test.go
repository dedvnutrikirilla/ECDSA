package ECDSA

import (
	"ECwrap"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"math/big"
	"testing"
)

var curve = elliptic.P256()

func TestVerifyOK(t *testing.T) {
	privateKey, err := KeyGen(curve)
	if err != nil {
		t.Fatalf("VerifyOk Keygen error = %v, expected = nil", err)
	}

	publicKey := privateKey.Pub
	hash := Hash("Hashed text. Valid.")
	sig := privateKey.Sign(hash)
	verifyRes := publicKey.Verify(sig, hash)
	if !verifyRes {
		t.Fatalf("VerifyOk verification result = %t, expected = true", verifyRes)
	}
}

func TestVerifyBadHash(t *testing.T) {
	privateKey, err := KeyGen(curve)
	if err != nil {
		t.Fatalf("VerifyBadHash Keygen error = %v, expected = nil", err)
	}

	publicKey := privateKey.Pub
	hashOk := Hash("Hashed text. Valid.")
	// intentionally compromise a valid hash value
	hashBad := Hash("Some other hash value. check me")
	sig := privateKey.Sign(hashOk)
	verifyRes := publicKey.Verify(sig, hashBad)
	if verifyRes {
		t.Fatalf("VerifyBadHash verification result = %t, expected = false", verifyRes)
	}
}

func TestVerifyBadPub(t *testing.T) {
	// verify with wrong public key
	privateKey, err := KeyGen(curve)
	if err != nil {
		t.Fatalf("VerifyBadPub Keygen error = %v, expected = nil", err)
	}
	publicKey := privateKey.Pub

	hash := Hash("Hashed text. Valid.")
	sig := privateKey.Sign(hash)
	Qrand, _ := ECwrap.RandPoint(curve)
	publicKey.Q = ECwrap.AddJacobian(publicKey.Q, Qrand, publicKey.Order)
	verifyRes := publicKey.Verify(sig, hash)
	if verifyRes {
		t.Fatalf("VerifyBadPub verification result = %t, expected = false", verifyRes)
	}
}

func TestVerifyStandart(t *testing.T) {
	// check with default crypyo/ecdsa package
	// key pair and signature from my ecdsa
	// verification from crypyo/ecdsa
	privateKey, err := KeyGen(curve)
	if err != nil {
		t.Fatalf("VerifyStandart Keygen error = %v, expected = nil", err)
	}
	publicKey := privateKey.Pub

	hash := Hash("Hashed text. Valid.")
	sig := privateKey.Sign(hash)
	Qrand, _ := ECwrap.RandPoint(curve)
	publicKey.Q = ECwrap.AddJacobian(publicKey.Q, Qrand, publicKey.Order)

	normPub := new(ecdsa.PublicKey)
	normPub.Curve = curve
	normPub.X = publicKey.Q.X
	normPub.Y = publicKey.Q.Y
	verifyRes := ecdsa.Verify(normPub, hash, sig.r, sig.s)

	if !verifyRes {
		t.Fatalf("VerifyStandart verification result = %t, expected = true", verifyRes)
	}
}

func TestVerifyStandart2(t *testing.T) {
	// check with default crypyo/ecdsa package
	// key pair and signature from crypyo/ecdsa
	// verification from my ecdsa
	privateKey, err := ecdsa.GenerateKey(curve, rand.Reader)
	if err != nil {
		t.Fatalf("VerifyStandart2 Keygen error = %v, expected = nil", err)
	}

	hash := Hash("Hashed text. Valid.")

	r, s, errsig := ecdsa.Sign(rand.Reader, privateKey, hash)
	if errsig != nil {
		t.Fatalf("VerifyStandart2 signing error = %v, expected = nil", errsig)
	}
	sig := new(Signature)
	sig.r, sig.s = r, s
	pubkey := new(PubKey)
	pubkey.N = curve.Params().N
	pubkey.Order = curve.Params().P
	pubkey.Q = new(ECwrap.ECPoint)
	pubkey.Pb = new(ECwrap.ECPoint)
	pubkey.Q.SetCoords(privateKey.PublicKey.X, privateKey.PublicKey.Y, big.NewInt(1))
	pubkey.Pb.SetCoords(curve.Params().Gx, curve.Params().Gy, big.NewInt(1))
	verifyRes := pubkey.Verify(sig, hash)
	if !verifyRes {
		t.Fatalf("VerifyStandart2 verification result = %t, expected = true", verifyRes)
	}
}
