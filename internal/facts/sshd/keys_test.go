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
	fp := func(b64 string) string {
		blob, err := base64.StdEncoding.DecodeString(b64)
		if err != nil {
			t.Fatal(err)
		}
		return Fingerprint(blob)
	}
	want := []PubKey{
		{Type: "ssh-ed25519", Bits: 256, Fingerprint: fp(ed)},
		{Type: "ssh-rsa", Bits: 4096, Fingerprint: fp(rsa4096)},
		{Type: "ssh-rsa", Bits: 1024, Fingerprint: fp(rsa1024)},
		{Type: "ssh-dss", Bits: 1024, Fingerprint: fp(dss)},
		{Type: "ecdsa-sha2-nistp384", Bits: 384, Fingerprint: fp(ec)},
	}
	if !reflect.DeepEqual(kl.Keys, want) {
		t.Errorf("keys\n got %+v\nwant %+v", kl.Keys, want)
	}
	if kl.Invalid != 2 {
		t.Errorf("invalid = %d, want 2", kl.Invalid)
	}
}

// TestFingerprintMatchesSSHKeygen pins the fingerprint format to what
// ssh-keygen -l prints for the same throwaway public key.
func TestFingerprintMatchesSSHKeygen(t *testing.T) {
	line := "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIIgZuuBDniWj4Y6Yt21RxilwC2HzZPZaPi4Gb0z43qpz test@example.com"
	kl := ParseKeys([]byte(line))
	if len(kl.Keys) != 1 {
		t.Fatalf("got %+v", kl)
	}
	if got, want := kl.Keys[0].Fingerprint, "SHA256:t7e3v4DmtoljcBouR0VN049G3GmJCSz1EC3Ht8oS5Yw"; got != want {
		t.Errorf("fingerprint = %s, want %s", got, want)
	}
}

func TestTruncatedBlob(t *testing.T) {
	short := base64.StdEncoding.EncodeToString([]byte{0, 0, 0, 7, 's', 's', 'h', '-', 'r', 's', 'a', 0, 0, 9})
	if kl := ParseKeys([]byte("ssh-rsa " + short)); len(kl.Keys) != 0 || kl.Invalid != 1 {
		t.Fatalf("got %+v", kl)
	}
}
