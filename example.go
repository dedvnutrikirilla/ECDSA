package ECDSA

import (
	"crypto/elliptic"
	"fmt"
	"log"
)

func main() {
	curve := elliptic.P256()
	priv, errkg := KeyGen(curve)
	if errkg != nil {
		log.Fatal(errkg)
	}
	pub := priv.Pub
	OutKey(priv)
	hash := Hash("SayMyName")
	sig := priv.Sign(hash)

	v := pub.Verify(sig, hash)
	fmt.Printf("Verify:%t\n", v)
}
