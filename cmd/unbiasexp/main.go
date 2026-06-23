package main

import (
	"crypto/sha512"
	"encoding/binary"
	"encoding/csv"
	"encoding/hex"
	"flag"
	"fmt"
	"log"
	"math"
	"math/bits"
	"os"

	falcon "DF_VRF/crypto"
)

func main() {
	numKeys := flag.Int("keys", 32, "number of independently generated keys")
	numInputs := flag.Int("inputs", 32, "number of inputs evaluated per key")
	modeName := flag.String("mode", "keccak", "VRF mode: shake or keccak")
	outPath := flag.String("out", "unbiasexp.csv", "output csv path")
	flag.Parse()

	mode := falcon.ModeKeccak
	switch *modeName {
	case "keccak":
		mode = falcon.ModeKeccak
	case "shake":
		mode = falcon.ModeSHAKE
	default:
		log.Fatalf("unknown mode %q; use shake or keccak", *modeName)
	}
	if *numKeys <= 0 || *numInputs <= 0 {
		log.Fatalf("keys and inputs must be positive")
	}

	f, err := os.Create(*outPath)
	if err != nil {
		log.Fatalf("create output file: %v", err)
	}
	defer f.Close()
	w := csv.NewWriter(f)
	defer w.Flush()
	if err := w.Write([]string{
		"key_index",
		"input_index",
		"pk_prefix_hex",
		"msg_hex",
		"proof_len",
		"beta_hex",
		"beta_lsb",
		"leading_zero_bits",
		"beta_head_u64",
	}); err != nil {
		log.Fatalf("write header: %v", err)
	}

	total := 0
	lsbOnes := 0
	prefix8 := 0
	prefix16 := 0
	byteFreq := make([]int, 256)
	bitOnes := 0
	totalBits := 0
	seen := make(map[falcon.VRFOutput]struct{}, (*numKeys)*(*numInputs))
	collisions := 0

	perKeyOnes := make([]int, *numKeys)
	perInputOnes := make([]int, *numInputs)

	for ki := 0; ki < *numKeys; ki++ {
		seed := deterministicBlock("DFVRF-UNBIAS-KEY", uint64(ki), 0)
		pk, sk, err := falcon.GenerateKey(seed)
		if err != nil {
			log.Fatalf("GenerateKey key=%d: %v", ki, err)
		}

		for xi := 0; xi < *numInputs; xi++ {
			msg := makeMessage(uint64(xi))
			proof, beta, err := sk.VRFProveWithMode(&pk, msg, mode)
			if err != nil {
				log.Fatalf("VRFProve key=%d input=%d: %v", ki, xi, err)
			}
			if beta2, err := pk.VRFVerifyWithMode(proof, msg, mode); err != nil || beta2 != beta {
				log.Fatalf("VRFVerify key=%d input=%d: beta mismatch or error: %v", ki, xi, err)
			}

			if _, ok := seen[beta]; ok {
				collisions++
			} else {
				seen[beta] = struct{}{}
			}

			lsb := int(beta[len(beta)-1] & 1)
			lsbOnes += lsb
			perKeyOnes[ki] += lsb
			perInputOnes[xi] += lsb
			lz := leadingZeroBits(beta[:])
			if lz >= 8 {
				prefix8++
			}
			if lz >= 16 {
				prefix16++
			}

			for _, b := range beta {
				byteFreq[b]++
				bitOnes += bits.OnesCount8(b)
				totalBits += 8
			}

			head64 := binary.BigEndian.Uint64(beta[:8])
			if err := w.Write([]string{
				fmt.Sprintf("%d", ki),
				fmt.Sprintf("%d", xi),
				hex.EncodeToString(pk[:8]),
				hex.EncodeToString(msg),
				fmt.Sprintf("%d", len(proof)),
				hex.EncodeToString(beta[:]),
				fmt.Sprintf("%d", lsb),
				fmt.Sprintf("%d", lz),
				fmt.Sprintf("%d", head64),
			}); err != nil {
				log.Fatalf("write row key=%d input=%d: %v", ki, xi, err)
			}
			total++
		}
	}

	expectedByte := float64(total*falcon.VRFBetaSize) / 256.0
	chi2 := 0.0
	for _, f := range byteFreq {
		diff := float64(f) - expectedByte
		chi2 += diff * diff / expectedByte
	}

	keyMin, keyMax, keyMean, keyStd := ratioStats(perKeyOnes, *numInputs)
	inputMin, inputMax, inputMean, inputStd := ratioStats(perInputOnes, *numKeys)
	lsbRatio := float64(lsbOnes) / float64(total)
	bitRatio := float64(bitOnes) / float64(totalBits)
	prefix8Ratio := float64(prefix8) / float64(total)
	prefix16Ratio := float64(prefix16) / float64(total)

	fmt.Printf("mode                       : %s\n", *modeName)
	fmt.Printf("keys / inputs / outputs    : %d / %d / %d\n", *numKeys, *numInputs, total)
	fmt.Printf("global beta bit-1 ratio    : %.6f\n", bitRatio)
	fmt.Printf("beta LSB predicate ratio   : %.6f (ideal 0.500000)\n", lsbRatio)
	fmt.Printf("per-key LSB ratio min/max  : %.6f / %.6f (mean %.6f, std %.6f)\n",
		keyMin, keyMax, keyMean, keyStd)
	fmt.Printf("per-input LSB ratio min/max: %.6f / %.6f (mean %.6f, std %.6f)\n",
		inputMin, inputMax, inputMean, inputStd)
	fmt.Printf("Pr[leading zeros >= 8]     : %.6f (ideal %.6f)\n", prefix8Ratio, 1.0/256.0)
	fmt.Printf("Pr[leading zeros >= 16]    : %.6f (ideal %.6f)\n", prefix16Ratio, 1.0/65536.0)
	fmt.Printf("byte chi-squared df=255    : %.2f\n", chi2)
	fmt.Printf("full beta collisions       : %d\n", collisions)
	fmt.Printf("csv written to             : %s\n", *outPath)
	fmt.Println("note: this is a statistical sanity check, not a proof of unbiasability.")
}

func deterministicBlock(label string, a, b uint64) []byte {
	out := make([]byte, 64)
	tmp := make([]byte, 32)
	copy(tmp, []byte(label))
	binary.BigEndian.PutUint64(tmp[16:24], a)
	binary.BigEndian.PutUint64(tmp[24:32], b)
	h1 := sha512.Sum512(tmp)
	binary.BigEndian.PutUint64(tmp[24:32], b+1)
	h2 := sha512.Sum512(tmp)
	copy(out[:32], h1[:32])
	copy(out[32:], h2[:32])
	return out
}

func makeMessage(i uint64) []byte {
	msg := make([]byte, 24)
	copy(msg[:16], []byte("DFVRF-UNBIAS-MSG"))
	binary.BigEndian.PutUint64(msg[16:], i)
	return msg
}

func leadingZeroBits(buf []byte) int {
	total := 0
	for _, b := range buf {
		if b == 0 {
			total += 8
			continue
		}
		return total + bits.LeadingZeros8(b)
	}
	return total
}

func ratioStats(counts []int, denom int) (min, max, mean, std float64) {
	min = 1.0
	for _, c := range counts {
		r := float64(c) / float64(denom)
		if r < min {
			min = r
		}
		if r > max {
			max = r
		}
		mean += r
	}
	mean /= float64(len(counts))
	for _, c := range counts {
		r := float64(c) / float64(denom)
		d := r - mean
		std += d * d
	}
	std = math.Sqrt(std / float64(len(counts)))
	return
}
