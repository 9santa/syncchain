package chain

import (
	"encoding/hex"
	"encoding/json"
	"fmt"
	"time"

	"github.com/dustinxie/ecc"
	"golang.org/x/crypto/sha3"
)

type Hash [32]byte

// Constructor generates hash
func NewHash(val any) Hash {
	jval, _ := json.Marshal(val)
	state := sha3.NewLegacyKeccak256()
	_, _ = state.Write(jval)
	hash := state.Sum(nil)
	return Hash(hash)
}

func (h Hash) String() string {
	return hex.EncodeToString(h[:])
}

func (h Hash) Bytes() []byte {
	hash := [32]byte(h)
	return hash[:]
}

func (h Hash) MarshalText() ([]byte, error) {
	return []byte(hex.EncodeToString(h[:])), nil
}

func (h Hash) UnmarshallText(hash []byte) error {
	_, err := hex.Decode(h[:], hash)
	return err
}

func DecodeHash(str string) (Hash, error) {
	var hash Hash
	bytes, err := hex.DecodeString(str)
	hash = Hash(bytes)
	return hash, err
}

// Transaction struct
type Tx struct {
	From  Address   `json:"from"`  // sender account address
	To    Address   `json:"to"`    // receiver account address
	Value uint64    `json:"value"` // value amount
	Nonce uint64    `json:"nonce"` // per account nonce
	Time  time.Time `json:"time"`  // time of transaction creation
}

func NewTx(from, to Address, val, nonce uint64) Tx {
	return Tx{From: from, To: to, Value: val, Nonce: nonce, Time: time.Now()}
}

func (t Tx) Hash() Hash {
	return NewHash(t)
}

// Signed Transaction type
type SigTx struct {
	Tx         // embedded original transaction
	Sig []byte `json:"sig"` // digital signature of the original transaction
}

func NewSigTx(tx Tx, sig []byte) SigTx {
	return SigTx{Tx: tx, Sig: sig}
}

// Produces Keccak256 hash of a signed transaction
func (t SigTx) Hash() Hash {
	return NewHash(t)
}

func (t SigTx) String() string {
	return fmt.Sprintf(
		"tx %.7s: %.7s -> %.7s %8d %8d", t.Hash(), t.From, t.To, t.Value, t.Nonce,
	)
}

// Pair hash is used for Merkle algorithms
func TxPairHash(l, r Hash) Hash {
	var nilHash Hash
	if r == nilHash {
		return l
	}
	return NewHash(l.String() + r.String())
}

// Transaction signing process requires owner's password and is performed from the sender's account
// Produce Keccak256 hash of the input transaction
// Sign Keccak256 hash of the transaction using the ECSDA algorithm on the Secp251k elliptic curve
// Construct the signed transaction by adding the produced digital signature to the original transaction
func (a Account) SignTx(tx Tx) (SigTx, error) {
	hash := tx.Hash().Bytes()
	sig, err := ecc.SignBytes(a.prv, hash, ecc.LowerS|ecc.RecID)
	if err != nil {
		return SigTx{}, err
	}
	sigtx := NewSigTx(tx, sig)
	return sigtx, nil
}

func VerifyTx(tx SigTx) (bool, error) {
	hash := tx.Tx.Hash().Bytes()
	pubkey, err := ecc.RecoverPubkey("P-256k1", hash, tx.Sig)
	if err != nil {
		return false, err
	}
	acc, _ := NewAddress(pubkey)
	return acc == tx.From, nil
}
