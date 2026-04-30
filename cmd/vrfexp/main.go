package main

import (
	"bytes"
	"encoding/binary"
	"encoding/csv"
	"encoding/hex"
	"flag"
	"fmt"
	"log"
	"os"

	"DF_VRF/crypto"
)

const two64 = 18446744073709551616.0

func main() {
	n := flag.Int("n", 10000, "number of VRF samples")
	outPath := flag.String("out", "vrf_samples.csv", "output csv path")
	flag.Parse()

	// 중요: empty seed 쓰지 말 것
	seed := []byte("falcon-vrf-experiment-seed-2026-04-21")

	pk, sk, err := falcon.GenerateKey(seed)
	if err != nil {
		log.Fatalf("GenerateKey failed: %v", err)
	}

	f, err := os.Create(*outPath)
	if err != nil {
		log.Fatalf("create output file failed: %v", err)
	}
	defer f.Close()

	w := csv.NewWriter(f)
	defer w.Flush()

	err = w.Write([]string{
		"i",
		"msg_hex",
		"proof_len",
		"beta_hex",
		"beta_head_u64",
		"u01",
		"s2_l2sq",
	})
	if err != nil {
		log.Fatalf("write header failed: %v", err)
	}

	seen64 := make(map[uint64]struct{}, *n)
	collisions64 := 0

	var bitOnes uint64
	var totalBits uint64

	minProofLen := int(^uint(0) >> 1)
	maxProofLen := 0
	var sumProofLen int64

	for i := 0; i < *n; i++ {
		msg := make([]byte, 16)
		copy(msg[:8], []byte("VRFEXP01"))
		binary.BigEndian.PutUint64(msg[8:], uint64(i))

		proof, beta, err := sk.VRFProve(&pk, msg)
		if err != nil {
			log.Fatalf("VRFProve failed at i=%d: %v", i, err)
		}

		beta2, err := pk.VRFVerify(proof, msg)
		if err != nil {
			log.Fatalf("VRFVerify failed at i=%d: %v", i, err)
		}
		if !bytes.Equal(beta[:], beta2[:]) {
			log.Fatalf("beta mismatch at i=%d", i)
		}

		proofLen := len(proof)
		if proofLen < minProofLen {
			minProofLen = proofLen
		}
		if proofLen > maxProofLen {
			maxProofLen = proofLen
		}
		sumProofLen += int64(proofLen)

		head64 := binary.BigEndian.Uint64(beta[:8])
		if _, ok := seen64[head64]; ok {
			collisions64++
		} else {
			seen64[head64] = struct{}{}
		}

		for _, b := range beta {
			for k := 0; k < 8; k++ {
				if ((b >> k) & 1) == 1 {
					bitOnes++
				}
				totalBits++
			}
		}

		// Falcon 내부 분포도 같이 보기
		sigCT, err := proof.ConvertToCT()
		if err != nil {
			log.Fatalf("ConvertToCT failed at i=%d: %v", i, err)
		}
		s2, err := sigCT.S2Coefficients()
		if err != nil {
			log.Fatalf("S2Coefficients failed at i=%d: %v", i, err)
		}
		var l2sq int64
		for _, x := range s2 {
			v := int64(x)
			l2sq += v * v
		}

		u01 := float64(head64) / two64

		err = w.Write([]string{
			fmt.Sprintf("%d", i),
			hex.EncodeToString(msg),
			fmt.Sprintf("%d", proofLen),
			hex.EncodeToString(beta[:]),
			fmt.Sprintf("%d", head64),
			fmt.Sprintf("%.17f", u01),
			fmt.Sprintf("%d", l2sq),
		})
		if err != nil {
			log.Fatalf("write row failed at i=%d: %v", i, err)
		}
	}

	fmt.Printf("samples               : %d\n", *n)
	fmt.Printf("proof_len min/max/avg : %d / %d / %.4f\n",
		minProofLen, maxProofLen, float64(sumProofLen)/float64(*n))
	fmt.Printf("truncated64 collisions: %d\n", collisions64)
	fmt.Printf("global bit-1 ratio    : %.6f\n", float64(bitOnes)/float64(totalBits))
	fmt.Printf("csv written to        : %s\n", *outPath)
}