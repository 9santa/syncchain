package chain

import (
	"encoding/hex"
	"encoding/json"

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
