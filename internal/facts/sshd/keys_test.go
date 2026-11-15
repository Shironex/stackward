package sshd

import (
	"encoding/base64"
	"encoding/binary"
	"math/big"
	"reflect"
	"strings"
	"testing"
)

// wire builds an SSH wire format blob from strings and big integers.
func wire(parts ...any) string {
	var b []byte
	put := func(x []byte) {
		var n [4]byte
		binary.BigEndian.PutUint32(n[:], uint32(len(x)))
		b = append(append(b, n[:]...), x...)
	}
	for _, p := range parts {
		switch v := p.(type) {
		case string:
			put([]byte(v))
		case *big.Int:
			put(append([]byte{0}, v.Bytes()...)) // mpint with a sign byte
		}
	}
	return base64.StdEncoding.EncodeToString(b)
}

func bitsInt(n int) *big.Int { return new(big.Int).Lsh(big.NewInt(1), uint(n-1)) }

func TestParseKeys(t *testing.T) {
	rsa4096 := wire("ssh-rsa", big.NewInt(65537), bitsInt(4096))
	rsa1024 := wire("ssh-rsa", big.NewInt(65537), bitsInt(1024))
	dss := wire("ssh-dss", bitsInt(1024), bitsInt(160), big.NewInt(2), big.NewInt(3))
	ed := wire("ssh-ed25519", strings.Repeat("k", 32))
	ec := wire("ecdsa-sha2-nistp384", "nistp384", "point")
	body := strings.Join([]string{
		"# comment",
		"",
		"ssh-ed25519 " + ed + " alice@example.com",
		`from="192.0.2.0/24",command="echo a b" ssh-rsa ` + rsa4096 + " backup key",
		"restrict,no-pty ssh-rsa " + rsa1024,
		"ssh-dss " + dss + " old",
		"ecdsa-sha2-nistp384 " + ec,
		"ssh-rsa " + ed + " type mismatch",
		"garbage line",
	}, "\n")
	kl := ParseKeys([]byte(body))
	want := []PubKey{
		{Type: "ssh-ed25519", Bits: 256},
		{Type: "ssh-rsa", Bits: 4096},
		{Type: "ssh-rsa", Bits: 1024},
		{Type: "ssh-dss", Bits: 1024},
		{Type: "ecdsa-sha2-nistp384", Bits: 384},
	}
	if !reflect.DeepEqual(kl.Keys, want) {
		t.Errorf("keys\n got %+v\nwant %+v", kl.Keys, want)
	}
	if kl.Invalid != 2 {
		t.Errorf("invalid = %d, want 2", kl.Invalid)
	}
}

func TestTruncatedBlob(t *testing.T) {
	short := base64.StdEncoding.EncodeToString([]byte{0, 0, 0, 7, 's', 's', 'h', '-', 'r', 's', 'a', 0, 0, 9})
	if kl := ParseKeys([]byte("ssh-rsa " + short)); len(kl.Keys) != 0 || kl.Invalid != 1 {
		t.Fatalf("got %+v", kl)
	}
}
