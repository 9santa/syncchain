package main

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"os"
	"path/filepath"

	"golang.org/x/crypto/sha3"

	"github.com/dustinxie/ecc"
)

// p256k1Key structs are used for JSON encoding/decoding
// Public key. X, Y are derived from the private key
type p256k1PublicKey struct {
	Curve string   `json:"curve"`
	X     *big.Int `json:"x"`
	Y     *big.Int `json:"y"`
}

func newP256k1PublicKey(pub *ecdsa.PublicKey) *p256k1PublicKey {
	return &p256k1PublicKey{Curve: "P-256k1", X: pub.X, Y: pub.Y}
}

// Private key
type p256k1PrivateKey struct {
	p256k1PublicKey          // Embedded public key
	D               *big.Int `json:"d"`
}

func newP256k1PrivateKey(prv *ecdsa.PrivateKey) *p256k1PrivateKey {
	return &p256k1PrivateKey{
		p256k1PublicKey: *newP256k1PublicKey(&prv.PublicKey),
		D:               prv.D,
	}
}

func (k *p256k1PrivateKey) publicKey() *ecdsa.PublicKey {
	return &ecdsa.PublicKey{Curve: ecc.P256k1(), X: k.X, Y: k.Y}
}

func (k *p256k1PrivateKey) privateKey() *ecdsa.PrivateKey {
	return &ecdsa.PrivateKey{PublicKey: *k.publicKey(), D: k.D}
}

type Address string

func NewAddress(pub *ecdsa.PublicKey) (Address, error) {
	// Passed key check
	if pub == nil || pub.X == nil || pub.Y == nil {
		return "", errors.New("nil public key")
	}

	// Ensure this is secp256k1
	if pub.Curve == nil || pub.Params() == nil || pub.Params().Name == "" {
		return "", errors.New("missing eliptic curve params")
	}

	// 32-byte big-endian X and Y (secp256k1 is 256-bit obv)
	x := pad32(pub.X)
	y := pad32(pub.Y)

	// Keccak256 over X concat Y
	ha := sha3.NewLegacyKeccak256()
	_, _ = ha.Write(x)
	_, _ = ha.Write(y)
	sum := ha.Sum(nil) // 32 bytes

	// last 20 bytes
	addr := sum[12:]
	return Address("0x" + hex.EncodeToString(addr)), nil
}

// Pad/cut to 32 bytes
func pad32(v *big.Int) []byte {
	b := v.Bytes()
	if len(b) > 32 { // shouldn't happen
		return b[len(b)-32:]
	}
	out := make([]byte, 32)
	copy(out[32-len(b):], b)
	return out
}

// Account: contains private key and account address derived from public key
type Account struct {
	prv  *ecdsa.PrivateKey
	addr Address
}

func NewAccount() (Account, error) {
	prv, err := ecdsa.GenerateKey(ecc.P256k1(), rand.Reader)
	if err != nil {
		return Account{}, err
	}
	addr, err := NewAddress(&prv.PublicKey)
	if err != nil {
		return Account{}, err
	}
	return Account{prv: prv, addr: addr}, nil
}

/*
Account persistence:
- Encode the account key pair
- Encrypt the encoded pair with owner's password
- Write encrypted pair to a file with restricted access
*/
func (a Account) WriteAccount(dir string, pass []byte) error {
	jprv, err := a.encodePrivateKey()
	if err != nil {
		return err
	}
	encPrv, err := encryptWithPassword(jprv, pass)
	if err != nil {
		return err
	}
	err = os.MkdirAll(dir, 0700)
	if err != nil {
		return err
	}
	path := filepath.Join(dir, string(a.addr))
	return os.WriteFile(path, encPrv, 0600) // 0600 - only the owner has access to read/write
}

/*
Account derivation:
- Read the encrypted key pair from a file
- Decrypt the encrypted key pair with owner's password
- Decode the encoded key pair
- Re-create the account from the decoded key pair
*/
func ReadAccount(path string, pass []byte) (Account, error) {
	encPrv, err := os.ReadFile(path)
	if err != nil {
		return Account{}, err
	}
	jprv, err := decryptWithPassword(encPrv, pass)
	if err != nil {
		return Account{}, err
	}
	return decodePrivateKey(jprv)
}

func (a Account) encodePrivateKey() ([]byte, error) {
	return json.Marshal(newP256k1PrivateKey(a.prv))
}

func decodePrivateKey(jprv []byte) (Account, error) {
	var pk p256k1PrivateKey
	err := json.Unmarshal(jprv, &pk)
	if err != nil {
		return Account{}, err
	}
	prv := pk.privateKey()
	addr, err := NewAddress(&prv.PublicKey)
	if err != nil {
		return Account{}, err
	}
	return Account{prv: prv, addr: addr}, nil
}

func prettyPrintJson(encoded []byte) error {
	var out bytes.Buffer
	if err := json.Indent(&out, encoded, "", " "); err != nil {
		fmt.Println(string(encoded))
		return err
	}

	fmt.Println(out.String())
	return nil
}
