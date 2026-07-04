package falcon

import (
	"crypto/rand"
	"fmt"
	"math"
	"testing"
)

const benchSamples = 1000

// BenchmarkKeyGen measures key generation throughput.
func BenchmarkKeyGen(b *testing.B) {
	seed := make([]byte, 64)
	rand.Read(seed)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		seed[0] = byte(i)
		seed[1] = byte(i >> 8)
		if _, _, err := GenerateKey(seed); err != nil {
			b.Fatal(err)
		}
	}
}

// BenchmarkVRFProve measures VRF proof generation throughput (SHAKE256 mode).
func BenchmarkVRFProve(b *testing.B) {
	seed := make([]byte, 64)
	rand.Read(seed)
	pub, priv, err := GenerateKey(seed)
	if err != nil {
		b.Fatal(err)
	}
	msg := make([]byte, 32)
	rand.Read(msg)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, _, err := priv.VRFProve(&pub, msg); err != nil {
			b.Fatal(err)
		}
	}
}

// BenchmarkVRFProveKeccak measures VRF proof generation throughput (Keccak256 mode).
func BenchmarkVRFProveKeccak(b *testing.B) {
	seed := make([]byte, 64)
	rand.Read(seed)
	pub, priv, err := GenerateKey(seed)
	if err != nil {
		b.Fatal(err)
	}
	msg := make([]byte, 32)
	rand.Read(msg)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, _, err := priv.VRFProveWithMode(&pub, msg, ModeKeccak); err != nil {
			b.Fatal(err)
		}
	}
}

// BenchmarkVRFVerify measures VRF proof verification throughput (SHAKE256 mode).
func BenchmarkVRFVerify(b *testing.B) {
	seed := make([]byte, 64)
	rand.Read(seed)
	pub, priv, err := GenerateKey(seed)
	if err != nil {
		b.Fatal(err)
	}
	msg := make([]byte, 32)
	rand.Read(msg)
	proof, _, err := priv.VRFProve(&pub, msg)
	if err != nil {
		b.Fatal(err)
	}
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, err := pub.VRFVerify(proof, msg); err != nil {
			b.Fatal(err)
		}
	}
}

// BenchmarkVRFVerifyKeccak measures VRF proof verification throughput (Keccak256 mode).
func BenchmarkVRFVerifyKeccak(b *testing.B) {
	seed := make([]byte, 64)
	rand.Read(seed)
	pub, priv, err := GenerateKey(seed)
	if err != nil {
		b.Fatal(err)
	}
	msg := make([]byte, 32)
	rand.Read(msg)
	proof, _, err := priv.VRFProveWithMode(&pub, msg, ModeKeccak)
	if err != nil {
		b.Fatal(err)
	}
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, err := pub.VRFVerifyWithMode(proof, msg, ModeKeccak); err != nil {
			b.Fatal(err)
		}
	}
}

// TestKeygenRejectionLoop measures the for(;;) iteration count in new_keygen
// across many key generations and reports the distribution.
//
// Interpretation: norm-bound acceptance alone would suggest E[k] around 4,
// but the actual loop also includes GS-bound checks and NTRU-solver failures.
// The parity filter (poly_small_mkgauss_choose) operates at coefficient level
// and does not contribute full-loop iterations.
//
// Run with: go test -v -run TestKeygenRejectionLoop
func TestKeygenRejectionLoop(t *testing.T) {
	const samples = 1000
	seed := make([]byte, 64)
	rand.Read(seed)

	counts := make([]int, samples)
	hist := make(map[int]int)

	for i := 0; i < samples; i++ {
		seed[0] = byte(i)
		seed[1] = byte(i >> 8)
		keygenCounterReset()
		if _, _, err := GenerateKey(seed); err != nil {
			t.Fatal(err)
		}
		c := keygenCounterGet()
		counts[i] = c
		hist[c]++
	}

	// Compute mean and stdev.
	var sum float64
	for _, c := range counts {
		sum += float64(c)
	}
	mean := sum / float64(samples)

	var varAcc float64
	minC, maxC := counts[0], counts[0]
	for _, c := range counts {
		d := float64(c) - mean
		varAcc += d * d
		if c < minC {
			minC = c
		}
		if c > maxC {
			maxC = c
		}
	}
	stdev := math.Sqrt(varAcc / float64(samples))

	fmt.Printf("\n=== DFalcon new_keygen Rejection Loop (n=%d) ===\n", samples)
	fmt.Printf("Iterations per keygen: min=%d  max=%d  mean=%.2f  stdev=%.2f\n",
		minC, maxC, mean, stdev)
	fmt.Printf("\nHistogram (iter → count):\n")
	for k := minC; k <= maxC; k++ {
		if hist[k] == 0 {
			continue
		}
		bar := ""
		for b := 0; b < hist[k]*40/samples; b++ {
			bar += "#"
		}
		fmt.Printf("  %2d: %4d  %s\n", k, hist[k], bar)
	}

	// Geometric(p) fit: p ≈ 1/mean; E[k] = 1/p.
	p := 1.0 / mean
	fmt.Printf("\nGeometric fit: p=%.3f  E[k]=%.2f\n", p, mean)
	fmt.Printf("Note: parity filter (poly_small_mkgauss_choose) adds 0 full-loop iterations;\n")
	fmt.Printf("      rejections come from norm-bound + GS-bound + NTRU-solver failures.\n")
}

// TestProofSizeDistribution prints proof size statistics over many samples.
// Run with: go test -v -run TestProofSizeDistribution
func TestProofSizeDistribution(t *testing.T) {
	seed := make([]byte, 64)
	rand.Read(seed)
	pub, priv, err := GenerateKey(seed)
	if err != nil {
		t.Fatal(err)
	}

	msg := make([]byte, 32)

	var totalShake, totalKeccak int
	minShake, maxShake := int(^uint(0)>>1), 0
	minKeccak, maxKeccak := int(^uint(0)>>1), 0

	for i := 0; i < benchSamples; i++ {
		rand.Read(msg)

		proofShake, _, err := priv.VRFProve(&pub, msg)
		if err != nil {
			t.Fatal(err)
		}
		proofKeccak, _, err := priv.VRFProveWithMode(&pub, msg, ModeKeccak)
		if err != nil {
			t.Fatal(err)
		}

		n := len(proofShake)
		totalShake += n
		if n < minShake {
			minShake = n
		}
		if n > maxShake {
			maxShake = n
		}

		n = len(proofKeccak)
		totalKeccak += n
		if n < minKeccak {
			minKeccak = n
		}
		if n > maxKeccak {
			maxKeccak = n
		}
	}

	fmt.Printf("\n=== DF-VRF Proof Size Distribution (n=%d samples) ===\n", benchSamples)
	fmt.Printf("\nMode       | Min   | Avg   | Max   | PubKey | Output\n")
	fmt.Printf("-----------|-------|-------|-------|--------|-------\n")
	fmt.Printf("SHAKE256   | %5d | %5d | %5d | %6d | %6d\n",
		minShake, totalShake/benchSamples, maxShake, PublicKeySize, VRFBetaSize)
	fmt.Printf("Keccak256  | %5d | %5d | %5d | %6d | %6d\n",
		minKeccak, totalKeccak/benchSamples, maxKeccak, PublicKeySize, VRFBetaSize)
	fmt.Printf("\nFixed sizes:\n")
	fmt.Printf("  Public key  : %d bytes\n", PublicKeySize)
	fmt.Printf("  Private key : %d bytes\n", PrivateKeySize)
	fmt.Printf("  VRF output  : %d bytes (SHA-512)\n", VRFBetaSize)
	fmt.Printf("  Proof max   : %d bytes\n", SignatureMaxSize)
}
