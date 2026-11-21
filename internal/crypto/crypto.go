// Package crypto implements application-level Encryption at Rest.
//
// Envelope scheme:
//   - KEK (key-encryption key, 256 bit) comes from ASI_MASTER_KEY or a 0600 key
//     file outside the database. It never touches the DB.
//   - DEK (data-encryption key, 256 bit) is random, stored in the DB only in
//     wrapped form (AES-256-GCM under the KEK). Rotating the KEK re-wraps the
//     DEK without re-encrypting data.
//   - Every sensitive column is sealed with AES-256-GCM under the DEK with a
//     fresh 96-bit nonce and AAD = "table.column", so ciphertext cannot be
//     moved between columns without detection.
//
// Stored format: "enc:v1:" + base64(nonce || ciphertext || tag).
package crypto

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

const Prefix = "enc:v1:"

var ErrNotEncrypted = errors.New("crypto: value is not an encrypted envelope")

func newAEAD(key []byte) (cipher.AEAD, error) {
	if len(key) != 32 {
		return nil, fmt.Errorf("crypto: key must be 32 bytes, got %d", len(key))
	}
	b, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	return cipher.NewGCM(b)
}

// RandomKey returns 32 bytes from the OS CSPRNG.
func RandomKey() []byte {
	k := make([]byte, 32)
	if _, err := rand.Read(k); err != nil {
		panic(err)
	}
	return k
}

// EncodeKey/DecodeKey use standard base64.
func EncodeKey(k []byte) string { return base64.StdEncoding.EncodeToString(k) }
func DecodeKey(s string) ([]byte, error) {
	k, err := base64.StdEncoding.DecodeString(strings.TrimSpace(s))
	if err != nil || len(k) != 32 {
		return nil, errors.New("crypto: master key must be base64-encoded 32 bytes (openssl rand -base64 32)")
	}
	return k, nil
}

// LoadKEK resolves the master key: env value first, then key file. When neither
// exists a new key file is generated with mode 0600. created reports that.
func LoadKEK(envValue, path string) (key []byte, created bool, err error) {
	if strings.TrimSpace(envValue) != "" {
		k, err := DecodeKey(envValue)
		return k, false, err
	}
	b, err := os.ReadFile(path)
	if err == nil {
		k, err := DecodeKey(string(b))
		if err != nil {
			return nil, false, fmt.Errorf("%s: %w", path, err)
		}
		return k, false, nil
	}
	if !os.IsNotExist(err) {
		return nil, false, err
	}
	k := RandomKey()
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return nil, false, err
	}
	if err := os.WriteFile(path, []byte(EncodeKey(k)+"\n"), 0o600); err != nil {
		return nil, false, err
	}
	return k, true, nil
}

func seal(a cipher.AEAD, aad string, pt []byte) string {
	nonce := make([]byte, a.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		panic(err)
	}
	out := a.Seal(nonce, nonce, pt, []byte(aad))
	return Prefix + base64.RawStdEncoding.EncodeToString(out)
}

func open(a cipher.AEAD, aad, s string) ([]byte, error) {
	if !strings.HasPrefix(s, Prefix) {
		return nil, ErrNotEncrypted
	}
	raw, err := base64.RawStdEncoding.DecodeString(s[len(Prefix):])
	if err != nil {
		return nil, fmt.Errorf("crypto: bad envelope encoding: %w", err)
	}
	ns := a.NonceSize()
	if len(raw) < ns+a.Overhead() {
		return nil, errors.New("crypto: envelope too short")
	}
	pt, err := a.Open(nil, raw[:ns], raw[ns:], []byte(aad))
	if err != nil {
		return nil, errors.New("crypto: authentication failed (wrong key, tampered data or wrong column)")
	}
	return pt, nil
}

const dekAAD = "asi:dek:v1"

// WrapKey seals the DEK under the KEK.
func WrapKey(kek, dek []byte) (string, error) {
	a, err := newAEAD(kek)
	if err != nil {
		return "", err
	}
	return seal(a, dekAAD, dek), nil
}

// UnwrapKey opens a wrapped DEK.
func UnwrapKey(kek []byte, wrapped string) ([]byte, error) {
	a, err := newAEAD(kek)
	if err != nil {
		return nil, err
	}
	dek, err := open(a, dekAAD, wrapped)
	if err != nil {
		return nil, fmt.Errorf("cannot unwrap data key - is ASI_MASTER_KEY correct? (%w)", err)
	}
	return dek, nil
}

// KeyCheck returns a short non-secret fingerprint of a key (for logs/UI).
func KeyCheck(k []byte) string {
	h := sha256.Sum256(append([]byte("asi:keycheck:"), k...))
	return hex.EncodeToString(h[:4])
}

// Keyring seals and opens field values with the DEK.
type Keyring struct {
	aead   cipher.AEAD
	idxKey []byte
	check  string
}

func NewKeyring(dek []byte) (*Keyring, error) {
	a, err := newAEAD(dek)
	if err != nil {
		return nil, err
	}
	m := hmac.New(sha256.New, dek)
	m.Write([]byte("asi:blind-index:v1"))
	return &Keyring{aead: a, idxKey: m.Sum(nil), check: KeyCheck(dek)}, nil
}

func (k *Keyring) Fingerprint() string { return k.check }

// Seal encrypts pt bound to aad. Empty input yields "" (no row-level leakage
// beyond emptiness, which keeps NULL-like semantics simple).
func (k *Keyring) Seal(aad string, pt []byte) string {
	if len(pt) == 0 {
		return ""
	}
	return seal(k.aead, aad, pt)
}

// Open decrypts a value produced by Seal. "" decrypts to nil.
func (k *Keyring) Open(aad, s string) ([]byte, error) {
	if s == "" {
		return nil, nil
	}
	return open(k.aead, aad, s)
}

func (k *Keyring) SealString(aad, s string) string { return k.Seal(aad, []byte(s)) }

// OpenString never fails loudly: undecryptable values are rendered as a marker
// so one corrupted field cannot break a whole listing.
func (k *Keyring) OpenString(aad, s string) string {
	b, err := k.Open(aad, s)
	if err != nil {
		return "[decryption error]"
	}
	return string(b)
}

func (k *Keyring) SealJSON(aad string, v any) (string, error) {
	if v == nil {
		return "", nil
	}
	b, err := json.Marshal(v)
	if err != nil {
		return "", err
	}
	if string(b) == "null" {
		return "", nil
	}
	return k.Seal(aad, b), nil
}

func (k *Keyring) MustSealJSON(aad string, v any) string {
	s, err := k.SealJSON(aad, v)
	if err != nil {
		panic(err)
	}
	return s
}

func (k *Keyring) OpenJSON(aad, s string, v any) error {
	b, err := k.Open(aad, s)
	if err != nil || len(b) == 0 {
		return err
	}
	return json.Unmarshal(b, v)
}

// BlindIndex is a keyed hash allowing equality lookups over encrypted values.
func (k *Keyring) BlindIndex(v string) string {
	m := hmac.New(sha256.New, k.idxKey)
	m.Write([]byte(strings.ToLower(strings.TrimSpace(v))))
	return hex.EncodeToString(m.Sum(nil)[:16])
}

func IsEncrypted(s string) bool { return strings.HasPrefix(s, Prefix) }
