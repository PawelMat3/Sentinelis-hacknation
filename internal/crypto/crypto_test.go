package crypto

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestSealOpenRoundTrip(t *testing.T) {
	k, err := NewKeyring(RandomKey())
	if err != nil {
		t.Fatal(err)
	}
	ct := k.SealString("services.http", "Set-Cookie: session=SECRET")
	if !IsEncrypted(ct) || strings.Contains(ct, "SECRET") {
		t.Fatalf("ciphertext leaks plaintext: %q", ct)
	}
	if got := k.OpenString("services.http", ct); got != "Set-Cookie: session=SECRET" {
		t.Fatalf("roundtrip mismatch: %q", got)
	}
	// Same plaintext twice -> different ciphertext (random nonce).
	if ct2 := k.SealString("services.http", "Set-Cookie: session=SECRET"); ct2 == ct {
		t.Fatal("nonce reuse: identical ciphertexts")
	}
}

func TestAADBindsColumn(t *testing.T) {
	k, _ := NewKeyring(RandomKey())
	ct := k.SealString("annotations.note", "secret note")
	if _, err := k.Open("services.http", ct); err == nil {
		t.Fatal("ciphertext moved to another column must not decrypt")
	}
}

func TestTamperDetected(t *testing.T) {
	k, _ := NewKeyring(RandomKey())
	ct := []byte(k.SealString("a.b", "payload-payload"))
	ct[len(ct)-3] ^= 0x01
	if _, err := k.Open("a.b", string(ct)); err == nil {
		t.Fatal("tampered ciphertext must fail authentication")
	}
}

func TestEmptyAndJSON(t *testing.T) {
	k, _ := NewKeyring(RandomKey())
	if k.SealString("x.y", "") != "" {
		t.Fatal("empty should stay empty")
	}
	type v struct{ A string }
	s, err := k.SealJSON("x.y", v{A: "hello"})
	if err != nil {
		t.Fatal(err)
	}
	var out v
	if err := k.OpenJSON("x.y", s, &out); err != nil || out.A != "hello" {
		t.Fatalf("json roundtrip: %v %+v", err, out)
	}
}

func TestWrapUnwrapAndWrongKEK(t *testing.T) {
	kek, dek := RandomKey(), RandomKey()
	w, err := WrapKey(kek, dek)
	if err != nil {
		t.Fatal(err)
	}
	got, err := UnwrapKey(kek, w)
	if err != nil || string(got) != string(dek) {
		t.Fatal("unwrap failed")
	}
	if _, err := UnwrapKey(RandomKey(), w); err == nil {
		t.Fatal("wrong KEK must not unwrap the DEK")
	}
}

func TestLoadKEKCreatesFile(t *testing.T) {
	p := filepath.Join(t.TempDir(), "sub", "master.key")
	k1, created, err := LoadKEK("", p)
	if err != nil || !created {
		t.Fatalf("expected creation: %v", err)
	}
	k2, created, err := LoadKEK("", p)
	if err != nil || created || string(k1) != string(k2) {
		t.Fatal("expected same key reloaded")
	}
	if _, err := os.Stat(p); err != nil {
		t.Fatal(err)
	}
	if _, _, err := LoadKEK("not-base64!!", p); err == nil {
		t.Fatal("invalid env key must fail")
	}
}

func TestBlindIndexStable(t *testing.T) {
	k, _ := NewKeyring(RandomKey())
	if k.BlindIndex("Admin") != k.BlindIndex(" admin ") {
		t.Fatal("blind index should normalise case/space")
	}
}
