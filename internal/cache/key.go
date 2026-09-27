package cache

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
)

// KeyFor serializes an input as canonical JSON and hashes it with SHA-256.
// encoding/json sorts map keys, making equivalent map-based configurations stable.
func KeyFor(namespace string, input any) (Key, error) {
	if !validNamespace(namespace) {
		return "", fmt.Errorf("invalid cache namespace %q", namespace)
	}
	canonical, err := json.Marshal(input)
	if err != nil {
		return "", fmt.Errorf("canonicalize cache key input: %w", err)
	}
	h := sha256.New()
	_, _ = h.Write([]byte(namespace))
	_, _ = h.Write([]byte{0})
	_, _ = h.Write(canonical)
	return Key(hex.EncodeToString(h.Sum(nil))), nil
}

// HashBytes returns the SHA-256 digest of content as lowercase hexadecimal.
func HashBytes(content []byte) string {
	h := sha256.Sum256(content)
	return hex.EncodeToString(h[:])
}

func validKey(key Key) bool {
	if len(key) != sha256.Size*2 {
		return false
	}
	_, err := hex.DecodeString(string(key))
	return err == nil
}

func validNamespace(namespace string) bool {
	if namespace == "" {
		return false
	}
	for _, r := range namespace {
		if (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9') || r == '-' || r == '_' {
			continue
		}
		return false
	}
	return true
}
