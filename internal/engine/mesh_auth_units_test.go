// Copyright (c) 2026 Reindert Pelsma
// SPDX-License-Identifier: ISC

//go:build !lite

package engine

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"testing"
)

// These tests pin the pure crypto helpers under mesh_control.go.
// The mesh handshake re-derives these on every challenge — if any
// of them silently changes (different label, swapped argument order,
// truncated nonce), every existing client suddenly fails to
// authenticate. The point is that the "wire format" of the auth
// derivation is load-bearing across versions.

func TestMeshAuthKeyDeterministic(t *testing.T) {
	ephemeral := bytes.Repeat([]byte{0x11}, 32)
	staticS := bytes.Repeat([]byte{0x22}, 32)
	a := meshAuthKey(ephemeral, staticS)
	b := meshAuthKey(ephemeral, staticS)
	if !bytes.Equal(a, b) {
		t.Fatal("meshAuthKey not deterministic")
	}
	if len(a) != sha256.Size {
		t.Fatalf("expected %d bytes, got %d", sha256.Size, len(a))
	}
}

func TestMeshAuthKeyDistinguishesInputs(t *testing.T) {
	base := meshAuthKey(bytes.Repeat([]byte{0x01}, 32), bytes.Repeat([]byte{0x02}, 32))
	otherEphemeral := meshAuthKey(bytes.Repeat([]byte{0x03}, 32), bytes.Repeat([]byte{0x02}, 32))
	otherStatic := meshAuthKey(bytes.Repeat([]byte{0x01}, 32), bytes.Repeat([]byte{0x04}, 32))
	if bytes.Equal(base, otherEphemeral) {
		t.Fatal("changing ephemeral must change auth key")
	}
	if bytes.Equal(base, otherStatic) {
		t.Fatal("changing static must change auth key")
	}
	if bytes.Equal(otherEphemeral, otherStatic) {
		t.Fatal("ephemeral-vs-static swap must produce different auth keys")
	}
}

func TestMeshAuthKeyDomainSeparated(t *testing.T) {
	// Asserts the "server-static" domain-separator is actually being
	// folded into the HMAC. A regression that drops it would make the
	// auth key equal to plain HMAC(ephemeral, static), losing the
	// label-binding that prevents misuse of the same key for other
	// purposes.
	ephemeral := bytes.Repeat([]byte{0xa1}, 32)
	staticS := bytes.Repeat([]byte{0xa2}, 32)
	got := meshAuthKey(ephemeral, staticS)

	// Reproduce the algorithm exactly so we'd notice if the production
	// path silently changed labels or argument order.
	mac := hmac.New(sha256.New, ephemeral)
	_, _ = mac.Write([]byte("server-static"))
	_, _ = mac.Write(staticS)
	want := mac.Sum(nil)
	if !bytes.Equal(got, want) {
		t.Fatalf("meshAuthKey wire format drift:\n got=%x\nwant=%x", got, want)
	}

	// Sanity: dropping the domain-separator changes the output.
	mac = hmac.New(sha256.New, ephemeral)
	_, _ = mac.Write(staticS)
	noLabel := mac.Sum(nil)
	if bytes.Equal(got, noLabel) {
		t.Fatal("auth key must include the domain separator")
	}
}

func TestMeshQuickCheckDeterministicAndLabelBound(t *testing.T) {
	pub := bytes.Repeat([]byte{0xc0}, 32)
	chal := bytes.Repeat([]byte{0xc1}, 32)
	bind := []byte("198.51.100.42")
	a := meshQuickCheck(pub, chal, bind)
	b := meshQuickCheck(pub, chal, bind)
	if !bytes.Equal(a, b) {
		t.Fatal("meshQuickCheck not deterministic")
	}
	c := meshQuickCheck(pub, chal, []byte("198.51.100.43"))
	if bytes.Equal(a, c) {
		t.Fatal("meshQuickCheck must change when address binding changes")
	}
}

func TestMeshSharedSecretDistinguishesAllInputs(t *testing.T) {
	k1 := bytes.Repeat([]byte{0xd1}, 32)
	k2 := bytes.Repeat([]byte{0xd2}, 32)
	psk := bytes.Repeat([]byte{0xd3}, 32)
	bind := []byte("198.51.100.10")
	base := meshSharedSecret(k1, k2, psk, bind)
	for i, alt := range [][4][]byte{
		{bytes.Repeat([]byte{0xee}, 32), k2, psk, bind},
		{k1, bytes.Repeat([]byte{0xee}, 32), psk, bind},
		{k1, k2, bytes.Repeat([]byte{0xee}, 32), bind},
		{k1, k2, psk, []byte("198.51.100.99")},
	} {
		got := meshSharedSecret(alt[0], alt[1], alt[2], alt[3])
		if bytes.Equal(got, base) {
			t.Fatalf("alt #%d collapsed to base secret", i)
		}
	}
	// Also pin: swapping k1 and k2 must NOT yield the same secret —
	// the inner/outer HMAC arrangement makes it asymmetric. A regression
	// that uses the same key for both layers would silently break this.
	swapped := meshSharedSecret(k2, k1, psk, bind)
	if bytes.Equal(swapped, base) {
		t.Fatal("k1/k2 swap collapsed — meshSharedSecret lost asymmetry")
	}
}

func TestMeshKeyNonceShape(t *testing.T) {
	secret := bytes.Repeat([]byte{0xff}, 32)
	for _, label := range []string{
		meshAuthContextLabel,
		meshBodyContextLabel,
		"unrelated-label",
	} {
		key, nonce := meshKeyNonce(secret, label)
		if len(key) != sha256.Size {
			t.Fatalf("%s: key wrong length %d", label, len(key))
		}
		// XChaCha20-Poly1305 nonce is 24 bytes; this is hardcoded in
		// the helper. If it ever changes, every sealed payload becomes
		// undecryptable.
		if len(nonce) != 24 {
			t.Fatalf("%s: nonce wrong length %d", label, len(nonce))
		}
		if bytes.Equal(key, nonce) {
			t.Fatalf("%s: key/nonce must derive from different inputs", label)
		}
	}
}

func TestMeshKeyNonceLabelSeparation(t *testing.T) {
	secret := bytes.Repeat([]byte{0x55}, 32)
	k1, n1 := meshKeyNonce(secret, "label-a")
	k2, n2 := meshKeyNonce(secret, "label-b")
	if bytes.Equal(k1, k2) {
		t.Fatal("different labels must yield different keys")
	}
	if bytes.Equal(n1, n2) {
		t.Fatal("different labels must yield different nonces")
	}
}

// TestMeshSealOpenRoundTrip — exercise the deterministic seal/open
// path together. This proves not only that the algorithm round-trips,
// but that a mismatched secret or label fails Open() cleanly with an
// error rather than silently returning garbage plaintext.
func TestMeshSealOpenRoundTrip(t *testing.T) {
	secret := bytes.Repeat([]byte{0x77}, 32)
	plain := []byte("super-secret-payload")
	sealed, err := meshSealDeterministic(plain, secret, "test-label")
	if err != nil {
		t.Fatal(err)
	}
	got, err := meshOpen(sealed, secret, "test-label")
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, plain) {
		t.Fatalf("round-trip mismatch: %q vs %q", got, plain)
	}

	// Wrong secret — must fail Open, not return junk.
	if _, err := meshOpen(sealed, bytes.Repeat([]byte{0x88}, 32), "test-label"); err == nil {
		t.Fatal("expected Open with wrong secret to error")
	}
	// Wrong label — must fail Open.
	if _, err := meshOpen(sealed, secret, "other-label"); err == nil {
		t.Fatal("expected Open with wrong label to error")
	}
	// Truncated payload — must fail Open with a clean error.
	if _, err := meshOpen(sealed[:5], secret, "test-label"); err == nil {
		t.Fatal("expected Open of short payload to error")
	}
}

// TestMeshSealDeterministicIsDeterministic — re-sealing the same
// plaintext under the same secret/label must produce the same
// ciphertext. The challenge-response handshake relies on this for
// reply binding; non-determinism here would be a security-relevant
// regression.
func TestMeshSealDeterministicIsDeterministic(t *testing.T) {
	secret := bytes.Repeat([]byte{0xab}, 32)
	plain := []byte("authn-bound-payload")
	a, err := meshSealDeterministic(plain, secret, meshAuthContextLabel)
	if err != nil {
		t.Fatal(err)
	}
	b, err := meshSealDeterministic(plain, secret, meshAuthContextLabel)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(a, b) {
		t.Fatal("meshSealDeterministic produced different ciphertexts for identical inputs")
	}

	// And: meshSealRandom must NOT produce the same output twice
	// (otherwise the nonce reuse would defeat the AEAD entirely).
	r1, err := meshSealRandom(plain, secret, meshAuthContextLabel)
	if err != nil {
		t.Fatal(err)
	}
	r2, err := meshSealRandom(plain, secret, meshAuthContextLabel)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Equal(r1, r2) {
		t.Fatal("meshSealRandom must use a fresh nonce each call")
	}
}
