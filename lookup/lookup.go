// Package lookup can be used to search PGP keys shared via public keyserver
package lookup

import (
	"context"
	"errors"
	"fmt"
	"io"
	"io/ioutil"
	"net/http"
	"net/url"
	"strings"

	"golang.org/x/crypto/openpgp"
)

// Lookup searches MIT PGP server for key by email
func Lookup(ctx context.Context, email string) (string, error) {

	const (
		begin  = "-----BEGIN PGP PUBLIC KEY BLOCK-----"
		end    = "-----END PGP PUBLIC KEY BLOCK-----"
		keystr = ";search=0x"
	)

	// 1-st call to get list of maching keys
	v := url.Values{}
	v.Set("op", "index")
	v.Set("search", email)
	s, err := get(ctx, v)
	if err != nil {
		return "", err
	}

	// Parse first key in the response
	bidx := strings.Index(s, keystr)
	l := bidx + len(keystr) + 16

	if bidx <= 0 || len(s) < l {
		return "", errors.New("no key was found")
	}

	// Example keyID: 0xA428256FF000508F
	keyID := s[l-18 : l]

	// 2-nd call to get key by ID
	v.Set("exact", "on")
	v.Set("op", "get")
	v.Set("search", keyID)
	s, err = get(ctx, v)
	if err != nil {
		return "", fmt.Errorf(keyID)
	}

	bidx = strings.Index(s, begin)
	eidx := strings.Index(s, end)
	if bidx <= 0 || eidx <= 0 || eidx < bidx {
		return "", errors.New("no key was found")
	}

	key := s[bidx : eidx+len(end)]
	keyring, err := openpgp.ReadArmoredKeyRing(strings.NewReader(key))
	if err != nil || len(keyring) < 1 {
		return "", errors.New("received bad key")
	}
	matched := false
	for _, v := range keyring[0].Identities {
		if v.UserId.Email == email {
			matched = true
			break
		}
	}

	if !matched {
		return "", errors.New("received key had email mismatch")
	}

	return key, nil

}

func get(ctx context.Context, values url.Values) (string, error) {
	req, err := url.Parse("https://pgp.mit.edu/pks/lookup")
	if err != nil {
		return "", fmt.Errorf("invalid base keyserver URL: %v", err)
	}
	req.RawQuery = values.Encode()
	r, err := http.NewRequest(http.MethodGet, req.String(), nil)
	if err != nil {
		return "", fmt.Errorf("cannot prepare request to keyserver: %v", err)
	}
	res, err := http.DefaultClient.Do(r.WithContext(ctx))
	if err != nil || res.StatusCode != http.StatusOK {
		return "", fmt.Errorf("key lookup request has failed: %v", err)
	}

	defer res.Body.Close()

	// Read only some reasonable amount of data,
	// account for some HTML and average key size
	const maxlen = 10000
	bytes, err := ioutil.ReadAll(io.LimitReader(res.Body, maxlen))
	if err != nil {
		return "", fmt.Errorf("cannot read response from keyserver: %v", err)
	}

	return string(bytes), nil
}
