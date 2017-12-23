package lookup_test

import (
	"context"
	"fmt"
	"log"
	"strings"
	"time"

	"github.com/antontsv/gpg/lookup"
	"golang.org/x/crypto/openpgp"
)

func ExampleLookup() {

	email := "lookup.example@antontsv.github.io"
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	// Fetch key:
	pubkey, err := lookup.Lookup(ctx, email)
	if err != nil {
		log.Fatalf("was not able to get key for %s from public key server: %v\n", email, err)
	}

	// Read key into keyring:
	keyring, err := openpgp.ReadArmoredKeyRing(strings.NewReader(pubkey))
	if err != nil || len(keyring) < 1 {
		log.Fatalf("received invalid key: %v\n", err)
	}

	// Check key info, like name, email, comment, etc
	for _, v := range keyring[0].Identities {
		fmt.Println(v.UserId.Name)
	}
	//Output: Go PGP Lookup example
}
