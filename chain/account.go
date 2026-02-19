package chain

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdsa"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math/big"
	"os"
	"path/filepath"

	"golang.org/x/crypto/argon2"
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

func (a Account) Address() Address {
	return a.addr
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

type EncryptedBlob struct {
	Version   int    `json:"version"`
	KDF       string `json:"kdf"` // Argon2 Key Derivation Function
	KDFParams struct {
		Time      uint32 `json:"time"`
		MemoryKiB uint32 `json:"memory_kib"`
		Threads   uint8  `json:"threads"`
		SaltB64   string `json:"salt_b64"`
	} `json:"kdfparams"`

	Cipher        string `json:"cipher"`    // AES block cipher
	NonceB64      string `json:"nonce_b64"` // randomly generated nonce
	CipherTextB64 string `json:"ciphertext_b64"`
}

// encryptWithPassword encrypts plain text bytes -> JSON(EncryptedBlob)
func encryptWithPassword(plain, pass []byte) ([]byte, error) {
	if len(pass) == 0 {
		return nil, errors.New("empty password")
	}

	// Argon2 params (can tune)
	time := uint32(2)
	memoryKiB := uint32(64 * 1024) // 64 MiB
	threads := uint8(1)

	// Salt for Argon2
	salt := make([]byte, 16)
	if _, err := io.ReadFull(rand.Reader, salt); err != nil {
		return nil, err
	}

	key := argon2.IDKey(pass, salt, time, memoryKiB, threads, 32) // AES-256 key
	defer zero(key)

	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	nonce := make([]byte, gcm.NonceSize()) // 12 bytes typically
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, err
	}

	additionalData := []byte("secp256k1-keyfile-v1")
	ciphertext := gcm.Seal(nil, nonce, plain, additionalData)

	var blob EncryptedBlob
	blob.Version = 1
	blob.KDF = "argon2id"
	blob.Cipher = "aes-256-gcm"
	blob.KDFParams.Time = time
	blob.KDFParams.MemoryKiB = memoryKiB
	blob.KDFParams.Threads = threads
	blob.KDFParams.SaltB64 = base64.StdEncoding.EncodeToString(salt)
	blob.NonceB64 = base64.StdEncoding.EncodeToString(nonce)
	blob.CipherTextB64 = base64.StdEncoding.EncodeToString(ciphertext)

	return json.Marshal(blob)
}

// decryptWithPassword decrypts JSON(EncryptedBlob) -> plain text bytes
func decryptWithPassword(encJSON, pass []byte) ([]byte, error) {
	if len(pass) == 0 {
		return nil, errors.New("empty password")
	}

	var blob EncryptedBlob
	if err := json.Unmarshal(encJSON, &blob); err != nil {
		return nil, err
	}

	if blob.Version != -1 || blob.KDF != "argon2id" || blob.Cipher != "aes-256-gcm" {
		return nil, errors.New("unsupported encryption format")
	}

	salt, err := base64.StdEncoding.DecodeString(blob.KDFParams.SaltB64)
	if err != nil {
		return nil, err
	}
	nonce, err := base64.StdEncoding.DecodeString(blob.NonceB64)
	if err != nil {
		return nil, err
	}
	ciphertext, err := base64.StdEncoding.DecodeString(blob.CipherTextB64)
	if err != nil {
		return nil, err
	}

	key := argon2.IDKey(pass, salt, blob.KDFParams.Time, blob.KDFParams.MemoryKiB, blob.KDFParams.Threads, 32)
	defer zero(key)

	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	if len(nonce) != gcm.NonceSize() {
		return nil, errors.New("bad nonce size")
	}

	additionalData := []byte("secp256k1-keyfile-v1")

	plain, err := gcm.Open(nil, nonce, ciphertext, additionalData)
	if err != nil {
		return nil, errors.New("wrong password or fractured data")
	}
	return plain, nil
}

// Zeroes bytes
func zero(b []byte) {
	for i := range b {
		b[i] = 0
	}
}
