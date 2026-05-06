package falcon

import (
	"crypto/rand"
	"fmt"
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
