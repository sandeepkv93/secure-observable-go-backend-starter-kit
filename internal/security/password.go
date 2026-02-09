package security

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"fmt"
	"math"
	"strings"

	"golang.org/x/crypto/argon2"
)

const (
	argonTime    uint32 = 3
	argonMemory  uint32 = 64 * 1024
	argonThreads uint8  = 2
	argonKeyLen  uint32 = 32
	argonSaltLen        = 16
)

func HashPassword(password string) (string, error) {
	salt := make([]byte, argonSaltLen)
	if _, err := rand.Read(salt); err != nil {
		return "", err
	}
	hash := argon2.IDKey([]byte(password), salt, argonTime, argonMemory, argonThreads, argonKeyLen)
	return fmt.Sprintf("$argon2id$v=19$m=%d,t=%d,p=%d$%s$%s",
		argonMemory, argonTime, argonThreads,
		base64.RawStdEncoding.EncodeToString(salt),
		base64.RawStdEncoding.EncodeToString(hash)), nil
}

func VerifyPassword(encoded, password string) (bool, error) {
	memory, timeCost, threads, salt, expected, err := decodeHash(encoded)
	if err != nil {
		return false, err
	}
	expectedLen := len(expected)
	if uint64(expectedLen) > uint64(math.MaxUint32) {
		return false, fmt.Errorf("invalid hash length")
	}
	// #nosec G115 -- bounded by explicit MaxUint32 check above.
	keyLen := uint32(expectedLen)
	actual := argon2.IDKey([]byte(password), salt, timeCost, memory, threads, keyLen)
	return subtle.ConstantTimeCompare(actual, expected) == 1, nil
}

func decodeHash(encoded string) (memory uint32, timeCost uint32, threads uint8, salt, hash []byte, err error) {
	parts := strings.Split(encoded, "$")
	if len(parts) != 6 || parts[1] != "argon2id" || parts[2] != "v=19" {
		return 0, 0, 0, nil, nil, fmt.Errorf("invalid password hash format")
	}
	if _, err = fmt.Sscanf(parts[3], "m=%d,t=%d,p=%d", &memory, &timeCost, &threads); err != nil {
		return 0, 0, 0, nil, nil, fmt.Errorf("invalid hash params")
	}
	salt, err = base64.RawStdEncoding.DecodeString(parts[4])
	if err != nil {
		return 0, 0, 0, nil, nil, fmt.Errorf("invalid hash salt")
	}
	hash, err = base64.RawStdEncoding.DecodeString(parts[5])
	if err != nil {
		return 0, 0, 0, nil, nil, fmt.Errorf("invalid hash payload")
	}
	return memory, timeCost, threads, salt, hash, nil
}
