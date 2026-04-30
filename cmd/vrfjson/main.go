// cmd/vrfjson: generates a Falcon-512 VRF proof and exports all data needed
// for on-chain verification as a JSON fixture file.
//
// Output fields:
//   seed           - key-generation seed (hex)
//   msg_hex        - signed message (hex)
//   transcript_hex - 64-byte VRF transcript SHA-512("FALCON-VRF-PROVE-v1"||pk||msg)
//   fixed_salt_hex - 40-byte deterministic salt for salt_version=0, logn=9 (Falcon-512)
//   pk_hex         - raw public key bytes
//   proof_hex      - compressed signature bytes (VRF proof)
//   beta_hex       - 64-byte VRF output
//   s2_words       - s2 polynomial packed as uint256 words (32 words, 16×16-bit each)
//   h_words        - public-key polynomial h packed as uint256 words (same layout)

package main

import (
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"math/big"
	"os"
	"path/filepath"

	falcon "DF_VRF/crypto"
)

const falconQ = 12289

// VRFFixture is the JSON structure written to disk.
type VRFFixture struct {
	Seed       string   `json:"seed"`
	MsgHex     string   `json:"msg_hex"`
	Transcript string   `json:"transcript_hex"`
	FixedSalt  string   `json:"fixed_salt_hex"`
	PkHex      string   `json:"pk_hex"`
	ProofHex   string   `json:"proof_hex"`
	BetaHex    string   `json:"beta_hex"`
	// Polynomial coefficients packed into uint256 words.
	// Each uint256 holds 16 coefficients in 16-bit slots (little-endian within word).
	// Falcon-512: 512 coefficients → 32 words.
	// Negative s2 values are reduced mod q before packing so each slot is uint16.
	S2Words []string `json:"s2_words"`
	HWords  []string `json:"h_words"`
}

// fixedSalt returns the 40-byte deterministic nonce for salt_version=0, logn=9 (Falcon-512).
//
//	dst[0] = salt_version (0)
//	dst[1] = FALCON_DET512_LOGN (9)
//	dst[2:12] = "FALCON_DET"
//	dst[12:40] = 0x00 (zero-padded)
func fixedSalt() []byte {
	salt := make([]byte, 40)
	salt[0] = 0x00
	salt[1] = 0x09 // logn = 9 (Falcon-512)
	copy(salt[2:], []byte("FALCON_DET"))
	return salt
}

// packInt16Coeffs packs a slice of int16 coefficients into uint256 words.
// Each word holds 16 coefficients, each in a 16-bit slot (j*16 bits from LSB).
// Negative values are mapped to [0, q) via v + q before packing.
func packInt16Coeffs(coeffs []int16) []string {
	numWords := (len(coeffs) + 15) / 16
	words := make([]string, numWords)
	for i := 0; i < numWords; i++ {
		w := new(big.Int)
		for j := 0; j < 16; j++ {
			idx := i*16 + j
			if idx >= len(coeffs) {
				break
			}
			v := int64(coeffs[idx])
			if v < 0 {
				v += falconQ
			}
			slot := new(big.Int).SetInt64(v)
			slot.Lsh(slot, uint(j*16))
			w.Or(w, slot)
		}
		words[i] = "0x" + fmt.Sprintf("%064x", w)
	}
	return words
}

// packUint16Coeffs packs a slice of uint16 coefficients into uint256 words.
func packUint16Coeffs(coeffs []uint16) []string {
	s := make([]int16, len(coeffs))
	for i, v := range coeffs {
		s[i] = int16(v)
	}
	return packInt16Coeffs(s)
}

func main() {
	out := flag.String("out", "vrf_fixture.json", "output JSON path")
	flag.Parse()

	seed := []byte("falcon-vrf-experiment-seed-2026-04-21")
	msg := []byte("hardhat-vrf-test-message")

	pk, sk, err := falcon.GenerateKey(seed)
	if err != nil {
		log.Fatalf("GenerateKey: %v", err)
	}

	proof, beta, err := sk.VRFProve(&pk, msg)
	if err != nil {
		log.Fatalf("VRFProve: %v", err)
	}

	betaVerify, err := pk.VRFVerify(proof, msg)
	if err != nil {
		log.Fatalf("VRFVerify: %v", err)
	}
	if beta != betaVerify {
		log.Fatal("beta mismatch between VRFProve and VRFVerify")
	}

	sigCT, err := proof.ConvertToCT()
	if err != nil {
		log.Fatalf("ConvertToCT: %v", err)
	}
	s2, err := sigCT.S2Coefficients()
	if err != nil {
		log.Fatalf("S2Coefficients: %v", err)
	}

	h, err := pk.Coefficients()
	if err != nil {
		log.Fatalf("Coefficients: %v", err)
	}

	transcript := falcon.MakeVRFTranscript(&pk, msg)

	if dir := filepath.Dir(*out); dir != "." {
		if err := os.MkdirAll(dir, 0o755); err != nil {
			log.Fatalf("mkdir %s: %v", dir, err)
		}
	}

	fixture := VRFFixture{
		Seed:       hex.EncodeToString(seed),
		MsgHex:     hex.EncodeToString(msg),
		Transcript: hex.EncodeToString(transcript[:]),
		FixedSalt:  hex.EncodeToString(fixedSalt()),
		PkHex:      hex.EncodeToString(pk[:]),
		ProofHex:   hex.EncodeToString(proof),
		BetaHex:    hex.EncodeToString(beta[:]),
		S2Words:    packInt16Coeffs(s2[:]),
		HWords:     packUint16Coeffs(h[:]),
	}

	data, err := json.MarshalIndent(fixture, "", "  ")
	if err != nil {
		log.Fatalf("json marshal: %v", err)
	}

	if err := os.WriteFile(*out, data, 0o644); err != nil {
		log.Fatalf("write %s: %v", *out, err)
	}

	fmt.Printf("VRF fixture written to %s\n", *out)
	fmt.Printf("  n              : %d (Falcon-512)\n", falcon.N)
	fmt.Printf("  s2_words count : %d\n", len(fixture.S2Words))
	fmt.Printf("  h_words count  : %d\n", len(fixture.HWords))
	fmt.Printf("  proof bytes    : %d\n", len(proof))
	fmt.Printf("  beta           : %s\n", fixture.BetaHex[:16]+"...")
}
