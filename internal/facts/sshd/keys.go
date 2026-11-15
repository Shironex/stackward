package sshd

import (
	"encoding/base64"
	"encoding/binary"
	"errors"
	"math/big"
	"strings"
)

// PubKey is what stackward keeps about one public key: its algorithm and
// size. Key material and comments (which often name people and machines)
// are never kept.
type PubKey struct {
	Type string `json:"type"`
	// Bits is the key size: the modulus for RSA, p for DSA, the curve size
	// for ECDSA and 256 for Ed25519. Zero when unknown (certificates).
	Bits int `json:"bits,omitempty"`
}

// KeyList is the result of parsing an authorized_keys or .pub file.
type KeyList struct {
	Keys []PubKey `json:"keys,omitempty"`
	// Invalid counts non comment lines that are not a parseable key.
	Invalid int `json:"invalid,omitempty"`
}

// ParseKeys parses authorized_keys(5) lines: optional options, then the key
// type, the base64 blob and an optional comment. Options may hold quoted
// spaces. Blank lines and # comments are skipped.
func ParseKeys(b []byte) KeyList {
	var kl KeyList
	for _, line := range strings.Split(string(b), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		if k, ok := parseKeyLine(line); ok {
			kl.Keys = append(kl.Keys, k)
		} else {
			kl.Invalid++
		}
	}
	return kl
}

func parseKeyLine(line string) (PubKey, bool) {
	toks := tokens(line)
	for i := 0; i+1 < len(toks); i++ {
		if !looksLikeKeyType(toks[i]) {
			continue
		}
		blob, err := base64.StdEncoding.DecodeString(toks[i+1])
		if err != nil {
			continue
		}
		k, err := describeBlob(blob)
		if err != nil || k.Type != toks[i] {
			continue
		}
		return k, true
	}
	return PubKey{}, false
}

// tokens splits on whitespace outside double quotes (options such as
// command="a b" keep their spaces).
func tokens(s string) []string {
	var out []string
	var cur strings.Builder
	quoted := false
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case c == '"':
			quoted = !quoted
			cur.WriteByte(c)
		case (c == ' ' || c == '\t') && !quoted:
			if cur.Len() > 0 {
				out = append(out, cur.String())
				cur.Reset()
			}
		case c == '\\' && quoted && i+1 < len(s):
			cur.WriteByte(c)
			i++
			cur.WriteByte(s[i])
		default:
			cur.WriteByte(c)
		}
	}
	if cur.Len() > 0 {
		out = append(out, cur.String())
	}
	return out
}

func looksLikeKeyType(s string) bool {
	return strings.HasPrefix(s, "ssh-") || strings.HasPrefix(s, "ecdsa-sha2-") || strings.HasPrefix(s, "sk-")
}

var errShort = errors.New("truncated key blob")

// readString reads one SSH wire format string (uint32 length, bytes).
func readString(b []byte) (val, rest []byte, err error) {
	if len(b) < 4 {
		return nil, nil, errShort
	}
	n := binary.BigEndian.Uint32(b)
	if int64(n) > int64(len(b))-4 {
		return nil, nil, errShort
	}
	return b[4 : 4+n], b[4+n:], nil
}

// describeBlob reads the key type and size from a public key blob.
func describeBlob(blob []byte) (PubKey, error) {
	typ, rest, err := readString(blob)
	if err != nil {
		return PubKey{}, err
	}
	k := PubKey{Type: string(typ)}
	switch k.Type {
	case "ssh-rsa":
		// string type, mpint e, mpint n
		_, rest, err = readString(rest) // e
		if err != nil {
			return k, err
		}
		n, _, err := readString(rest)
		if err != nil {
			return k, err
		}
		k.Bits = new(big.Int).SetBytes(n).BitLen()
	case "ssh-dss":
		// string type, mpint p, q, g, y
		p, _, err := readString(rest)
		if err != nil {
			return k, err
		}
		k.Bits = new(big.Int).SetBytes(p).BitLen()
	case "ecdsa-sha2-nistp256", "sk-ecdsa-sha2-nistp256@openssh.com":
		k.Bits = 256
	case "ecdsa-sha2-nistp384":
		k.Bits = 384
	case "ecdsa-sha2-nistp521":
		k.Bits = 521
	case "ssh-ed25519", "sk-ssh-ed25519@openssh.com":
		k.Bits = 256
	}
	return k, nil
}
