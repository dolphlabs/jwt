package main

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"strings"
	"time"
)

const iterations = 1000
const maxClaimFields = 256
const headerJSON = `{"alg":"HS256","typ":"JWT"}`

var key = []byte("01234567890123456789012345678901")

type Claims struct {
	Sub  string `json:"sub"`
	Exp  int64  `json:"exp"`
	Role string `json:"role"`
}

type Header struct {
	Alg  string          `json:"alg"`
	Typ  string          `json:"typ"`
	Crit json.RawMessage `json:"crit"`
	B64  json.RawMessage `json:"b64"`
}

func encodeSegment(data []byte) string {
	return base64.RawURLEncoding.EncodeToString(data)
}

func sign(claims Claims) (string, error) {
	if len(key) < 32 {
		return "", fmt.Errorf("short key")
	}
	payload, err := json.Marshal(claims)
	if err != nil {
		return "", err
	}
	if len(payload) > 16*1024 {
		return "", fmt.Errorf("payload too large")
	}
	input := encodeSegment([]byte(headerJSON)) + "." + encodeSegment(payload)
	mac := hmac.New(sha256.New, key)
	_, _ = mac.Write([]byte(input))
	token := input + "." + encodeSegment(mac.Sum(nil))
	if len(token) > 16*1024 {
		return "", fmt.Errorf("token too large")
	}
	return token, nil
}

func checkUniqueClaims(payload []byte) error {
	decoder := json.NewDecoder(bytes.NewReader(payload))
	first, err := decoder.Token()
	if err != nil || first != json.Delim('{') {
		return fmt.Errorf("claims must be an object")
	}
	seen := make(map[string]struct{}, 8)
	count := 0
	for decoder.More() {
		field, err := decoder.Token()
		if err != nil {
			return err
		}
		name, ok := field.(string)
		if !ok {
			return fmt.Errorf("invalid claim name")
		}
		count++
		if count > maxClaimFields {
			return fmt.Errorf("too many claim fields")
		}
		if _, exists := seen[name]; exists {
			return fmt.Errorf("duplicate claim field")
		}
		seen[name] = struct{}{}
		var value json.RawMessage
		if err := decoder.Decode(&value); err != nil {
			return err
		}
	}
	if _, err = decoder.Token(); err != nil {
		return err
	}
	if _, err = decoder.Token(); err != io.EOF {
		return fmt.Errorf("trailing JSON data")
	}
	return nil
}

func checkHeader(raw []byte) error {
	decoder := json.NewDecoder(bytes.NewReader(raw))
	first, err := decoder.Token()
	if err != nil || first != json.Delim('{') {
		return fmt.Errorf("header must be an object")
	}
	seenAlg, seenTyp := false, false
	for decoder.More() {
		field, err := decoder.Token()
		if err != nil {
			return err
		}
		name, ok := field.(string)
		if !ok || name == "crit" || name == "b64" {
			return fmt.Errorf("unsupported protected header")
		}
		if name == "alg" {
			if seenAlg {
				return fmt.Errorf("duplicate alg")
			}
			seenAlg = true
		}
		if name == "typ" {
			if seenTyp {
				return fmt.Errorf("duplicate typ")
			}
			seenTyp = true
		}
		var value json.RawMessage
		if err := decoder.Decode(&value); err != nil {
			return err
		}
		if name == "typ" && bytes.Equal(bytes.TrimSpace(value), []byte("null")) {
			return fmt.Errorf("null typ")
		}
	}
	if _, err := decoder.Token(); err != nil {
		return err
	}
	if _, err := decoder.Token(); err != io.EOF {
		return fmt.Errorf("trailing header data")
	}
	if !seenAlg {
		return fmt.Errorf("missing alg")
	}
	return nil
}

func verify(token string) (Claims, error) {
	var claims Claims
	if len(key) < 32 || len(token) > 16*1024 {
		return claims, fmt.Errorf("invalid key or token size")
	}
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return claims, fmt.Errorf("bad segment count")
	}
	input := parts[0] + "." + parts[1]
	headerBytes, err := base64.RawURLEncoding.Strict().DecodeString(parts[0])
	if err != nil || encodeSegment(headerBytes) != parts[0] {
		return claims, fmt.Errorf("bad header encoding")
	}
	var header Header
	if err = json.Unmarshal(headerBytes, &header); err != nil || header.Alg != "HS256" ||
		len(header.Crit) != 0 || len(header.B64) != 0 {
		return claims, fmt.Errorf("unsupported header")
	}
	if err = checkHeader(headerBytes); err != nil {
		return claims, err
	}
	want, err := base64.RawURLEncoding.Strict().DecodeString(parts[2])
	if err != nil || encodeSegment(want) != parts[2] {
		return claims, err
	}
	mac := hmac.New(sha256.New, key)
	_, _ = mac.Write([]byte(input))
	if !hmac.Equal(want, mac.Sum(nil)) {
		return claims, fmt.Errorf("bad mac")
	}
	payload, err := base64.RawURLEncoding.Strict().DecodeString(parts[1])
	if err != nil || encodeSegment(payload) != parts[1] || len(payload) == 0 || payload[0] != '{' {
		return claims, err
	}
	if err = checkUniqueClaims(payload); err != nil {
		return claims, err
	}
	if err = json.Unmarshal(payload, &claims); err != nil {
		return claims, err
	}
	return claims, nil
}

func main() {
	claims := Claims{Sub: "user-7", Exp: 2000000000, Role: "reader"}
	token, err := sign(claims)
	if err != nil {
		panic(err)
	}
	if _, err = verify(token); err != nil {
		panic(err)
	}
	fmt.Printf("T %s\n", token)
	signSamples := make([]int64, iterations)
	checksum := 0
	signBatchStart := time.Now()
	for i := range signSamples {
		started := time.Now()
		generated, signErr := sign(claims)
		elapsed := time.Since(started)
		if signErr != nil {
			panic(signErr)
		}
		checksum += len(generated)
		signSamples[i] = elapsed.Nanoseconds()
	}
	signBatchElapsed := time.Since(signBatchStart)

	verifySamples := make([]int64, iterations)
	verifyBatchStart := time.Now()
	for i := range verifySamples {
		started := time.Now()
		checked, verifyErr := verify(token)
		elapsed := time.Since(started)
		if verifyErr != nil {
			panic(verifyErr)
		}
		checksum += len(checked.Sub) + int(checked.Exp)
		verifySamples[i] = elapsed.Nanoseconds()
	}
	verifyBatchElapsed := time.Since(verifyBatchStart)

	fmt.Printf("B S %d\n", signBatchElapsed.Nanoseconds())
	for _, ns := range signSamples {
		fmt.Printf("S %d\n", ns)
	}
	fmt.Printf("B V %d\n", verifyBatchElapsed.Nanoseconds())
	for _, ns := range verifySamples {
		fmt.Printf("V %d\n", ns)
	}
	fmt.Printf("C %d\n", checksum)
}
