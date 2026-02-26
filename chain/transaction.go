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
func NewHash(val any) (Hash, error) {
	jval, err := json.Marshal(val)
	if err != nil {
		return Hash{}, err
	}
	state := sha3.NewLegacyKeccak256()
	_, _ = state.Write(jval)
	sum := state.Sum(nil) // []byte len 32
	var out Hash
	copy(out[:], sum)
	return out, nil
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

func (h Hash) UnmarshalText(hash []byte) error {
	decoded := make([]byte, hex.DecodedLen(len(hash)))
	n, err := hex.Decode(decoded, hash)
	if err != nil {
		return err
	}
	if n != 32 {
		return fmt.Errorf("hash must be 32 bytes, got %d", n)
	}
	copy(h[:], hash[:])
	return err
}

func DecodeHash(str string) (Hash, error) {
	b, err := hex.DecodeString(str)
	if err != nil {
		return Hash{}, err
	}
	if len(b) != 32 {
		return Hash{}, fmt.Errorf("hash must be 32 bytes, got %d", len(b))
	}
	var h Hash
	copy(h[:], b)
	return h, nil
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
	return Tx{From: from, To: to, Value: val, Nonce: nonce, Time: time.Now().UTC()}
}

func (t Tx) Hash() Hash {
	h, _ := NewHash(t)
	return h
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
	h, _ := NewHash(t)
	return h
}

func (t SigTx) String() string {
	return fmt.Sprintf(
		"tx %.7s: %.7s -> %.7s %8d %8d", t.Hash(), t.From, t.To, t.Value, t.Nonce,
	)
}

// Pair hash is used for Merkle algorithms
func TxPairHash(l, r Hash) (Hash, error) {
	var nilHash Hash
	if r == nilHash {
		return l, nil
	}
	combined := make([]byte, 0, 64)
	combined = append(combined, l[:]...)
	combined = append(combined, r[:]...)
	return NewHash(combined)
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
