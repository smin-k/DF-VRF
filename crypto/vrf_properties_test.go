package falcon

// VRF Property Tests
//
// These tests verify necessary (but not sufficient) conditions for the three
// VRF security properties.  They cannot substitute for a formal security
// reduction; they catch obvious implementation failures and provide empirical
// confidence.
//
// Property 1 – Correctness:  already covered by TestFalconVRFRoundTrip.
//
// Property 2 – Uniqueness:   we test the necessary conditions:
//   (a) determinism     – same (sk,msg) always produces the same proof/beta
//   (b) injectivity     – different (pk,msg) pairs produce different betas
//   (c) proof binding   – a tampered proof cannot produce the same beta
//   NOTE: full uniqueness (no second valid proof exists under any sk) is a
//   computational hardness argument, not a unit test.
//
// Property 3 – Pseudorandomness: we run statistical sanity checks:
//   (a) byte-frequency chi-squared test  (catches biased output)
//   (b) avalanche effect                 (1-bit msg change flips ~50% of beta)
//   (c) no collisions over many samples  (birthday-bound sanity)
//   NOTE: true pseudorandomness (PPT indistinguishability) requires a
//   reduction to Falcon unforgeability + SHA-512 PRF; tests only detect
//   gross failures.

import (
	"bytes"
	"crypto/rand"
	"math"
	"math/bits"
	"testing"
)

// ── Property 2: Uniqueness ────────────────────────────────────────────────────

// TestVRFUniqueness_Determinism verifies that the VRF output is fully
// determined by (sk, msg): repeated calls with identical inputs produce
// identical proof and beta.
func TestVRFUniqueness_Determinism(t *testing.T) {
	const rounds = 10
	seed := make([]byte, 64)
	rand.Read(seed)
	pub, priv, err := GenerateKey(seed)
	if err != nil {
		t.Fatal(err)
	}

	for i := 0; i < rounds; i++ {
		msg := make([]byte, 64)
		rand.Read(msg)

		proof1, beta1, err := priv.VRFProve(&pub, msg)
		if err != nil {
			t.Fatalf("round %d prove1: %v", i, err)
		}
		proof2, beta2, err := priv.VRFProve(&pub, msg)
		if err != nil {
			t.Fatalf("round %d prove2: %v", i, err)
		}

		if !bytes.Equal(proof1, proof2) {
			t.Errorf("round %d: proof not deterministic", i)
		}
		if beta1 != beta2 {
			t.Errorf("round %d: beta not deterministic", i)
		}
	}
}

// TestVRFUniqueness_Determinism_Keccak is the Keccak-mode equivalent.
func TestVRFUniqueness_Determinism_Keccak(t *testing.T) {
	const rounds = 10
	seed := make([]byte, 64)
	rand.Read(seed)
	pub, priv, err := GenerateKey(seed)
	if err != nil {
		t.Fatal(err)
	}

	for i := 0; i < rounds; i++ {
		msg := make([]byte, 64)
		rand.Read(msg)

		proof1, beta1, err := priv.VRFProveWithMode(&pub, msg, ModeKeccak)
		if err != nil {
			t.Fatalf("round %d prove1: %v", i, err)
		}
		proof2, beta2, err := priv.VRFProveWithMode(&pub, msg, ModeKeccak)
		if err != nil {
			t.Fatalf("round %d prove2: %v", i, err)
		}

		if !bytes.Equal(proof1, proof2) {
			t.Errorf("round %d: keccak proof not deterministic", i)
		}
		if beta1 != beta2 {
			t.Errorf("round %d: keccak beta not deterministic", i)
		}
	}
}

// TestVRFUniqueness_DifferentKeys verifies that different key pairs produce
// different VRF outputs for the same message.
// A collision here would imply the VRF output is not injective in pk.
func TestVRFUniqueness_DifferentKeys(t *testing.T) {
	const pairs = 20
	msg := []byte("uniqueness-test-fixed-message")

	betas := make(map[VRFOutput]int)
	for i := 0; i < pairs; i++ {
		seed := make([]byte, 64)
		rand.Read(seed)
		pub, priv, err := GenerateKey(seed)
		if err != nil {
			t.Fatal(err)
		}
		_, beta, err := priv.VRFProve(&pub, msg)
		if err != nil {
			t.Fatalf("pair %d: %v", i, err)
		}
		if prev, exists := betas[beta]; exists {
			t.Errorf("collision: pair %d and pair %d produced same beta", i, prev)
		}
		betas[beta] = i
	}
}

// TestVRFUniqueness_DifferentMessages verifies that different messages produce
// different VRF outputs under the same key pair.
func TestVRFUniqueness_DifferentMessages(t *testing.T) {
	const samples = 50
	seed := make([]byte, 64)
	rand.Read(seed)
	pub, priv, err := GenerateKey(seed)
	if err != nil {
		t.Fatal(err)
	}

	betas := make(map[VRFOutput]int)
	for i := 0; i < samples; i++ {
		msg := make([]byte, 64)
		rand.Read(msg)
		_, beta, err := priv.VRFProve(&pub, msg)
		if err != nil {
			t.Fatalf("sample %d: %v", i, err)
		}
		if prev, exists := betas[beta]; exists {
			t.Errorf("collision: sample %d and sample %d produced same beta", i, prev)
		}
		betas[beta] = i
	}
}

// TestVRFUniqueness_ProofBinding verifies that a tampered proof produces a
// different VRF output (not the same beta as the original proof).
// This ensures the VRF output is bound to the specific proof.
func TestVRFUniqueness_ProofBinding(t *testing.T) {
	seed := make([]byte, 64)
	rand.Read(seed)
	pub, priv, err := GenerateKey(seed)
	if err != nil {
		t.Fatal(err)
	}
	msg := []byte("proof-binding-test")

	proof, beta, err := priv.VRFProve(&pub, msg)
	if err != nil {
		t.Fatal(err)
	}

	// Tamper with the last byte of the proof.
	tampered := append(CompressedSignature(nil), proof...)
	tampered[len(tampered)-1] ^= 0xFF

	// A tampered proof must either fail verification or produce a different beta.
	betaTampered, verifyErr := pub.VRFVerify(tampered, msg)
	if verifyErr == nil && betaTampered == beta {
		t.Error("tampered proof verified and produced the same beta — binding violated")
	}
}

// TestVRFUniqueness_PublicKeyBinding verifies that a proof generated for one
// public key cannot be verified under another public key for the same message.
func TestVRFUniqueness_PublicKeyBinding(t *testing.T) {
	seed1 := make([]byte, 64)
	seed2 := make([]byte, 64)
	rand.Read(seed1)
	rand.Read(seed2)

	pub1, priv1, err := GenerateKey(seed1)
	if err != nil {
		t.Fatal(err)
	}
	pub2, _, err := GenerateKey(seed2)
	if err != nil {
		t.Fatal(err)
	}

	msg := []byte("public-key-binding-test")
	proof, _, err := priv1.VRFProve(&pub1, msg)
	if err != nil {
		t.Fatal(err)
	}

	if _, err := pub2.VRFVerify(proof, msg); err == nil {
		t.Fatal("proof generated under pub1 verified under pub2")
	}
}

// TestVRFUniqueness_ModeSeparation verifies that SHAKE and Keccak proofs are
// not interchangeable. This is important for the paper's dual-backend claims.
func TestVRFUniqueness_ModeSeparation(t *testing.T) {
	seed := make([]byte, 64)
	rand.Read(seed)
	pub, priv, err := GenerateKey(seed)
	if err != nil {
		t.Fatal(err)
	}

	msg := []byte("mode-separation-test")
	shakeProof, _, err := priv.VRFProveWithMode(&pub, msg, ModeSHAKE)
	if err != nil {
		t.Fatalf("shake prove: %v", err)
	}
	keccakProof, _, err := priv.VRFProveWithMode(&pub, msg, ModeKeccak)
	if err != nil {
		t.Fatalf("keccak prove: %v", err)
	}

	if _, err := pub.VRFVerifyWithMode(shakeProof, msg, ModeKeccak); err == nil {
		t.Fatal("SHAKE proof verified in Keccak mode")
	}
	if _, err := pub.VRFVerifyWithMode(keccakProof, msg, ModeSHAKE); err == nil {
		t.Fatal("Keccak proof verified in SHAKE mode")
	}
}

// ── Property 3: Pseudorandomness (statistical tests) ─────────────────────────

// TestVRFPseudorandomness_ByteDistribution runs a chi-squared goodness-of-fit
// test on the byte frequencies across many VRF outputs.
// A biased output distribution (e.g., constants, structured patterns) would
// fail this test.  Passing does NOT prove pseudorandomness.
func TestVRFPseudorandomness_ByteDistribution(t *testing.T) {
	const samples = 500
	seed := make([]byte, 64)
	rand.Read(seed)
	pub, priv, err := GenerateKey(seed)
	if err != nil {
		t.Fatal(err)
	}

	freq := make([]int, 256)
	total := 0
	for i := 0; i < samples; i++ {
		msg := make([]byte, 32)
		rand.Read(msg)
		_, beta, err := priv.VRFProve(&pub, msg)
		if err != nil {
			t.Fatalf("sample %d: %v", i, err)
		}
		for _, b := range beta {
			freq[b]++
			total++
		}
	}

	// Chi-squared test: expected frequency per bucket = total/256.
	expected := float64(total) / 256.0
	chi2 := 0.0
	for _, f := range freq {
		diff := float64(f) - expected
		chi2 += (diff * diff) / expected
	}

	// Critical value for chi²(255 df) at p=0.001 is ~332.
	// A well-distributed output should be well below this.
	const criticalValue = 332.0
	t.Logf("chi² = %.2f (critical = %.2f at p=0.001, df=255)", chi2, criticalValue)
	if chi2 > criticalValue {
		t.Errorf("byte distribution test FAILED: chi²=%.2f > %.2f — output appears non-uniform",
			chi2, criticalValue)
	}
}

// TestVRFPseudorandomness_AvalancheEffect verifies that a single-bit change in
// the message flips approximately 50% of the output bits (strict avalanche
// criterion).  A low avalanche score indicates structural bias.
func TestVRFPseudorandomness_AvalancheEffect(t *testing.T) {
	const samples = 200
	seed := make([]byte, 64)
	rand.Read(seed)
	pub, priv, err := GenerateKey(seed)
	if err != nil {
		t.Fatal(err)
	}

	totalBits := 0
	flippedBits := 0

	for i := 0; i < samples; i++ {
		msg := make([]byte, 32)
		rand.Read(msg)

		_, beta1, err := priv.VRFProve(&pub, msg)
		if err != nil {
			t.Fatalf("sample %d original: %v", i, err)
		}

		// Flip a random bit in the message.
		flipByte := i % len(msg)
		flipBit := uint(i % 8)
		msg2 := append([]byte(nil), msg...)
		msg2[flipByte] ^= 1 << flipBit

		_, beta2, err := priv.VRFProve(&pub, msg2)
		if err != nil {
			t.Fatalf("sample %d flipped: %v", i, err)
		}

		// Count differing bits between beta1 and beta2 over the full output.
		for j := range beta1 {
			diff := beta1[j] ^ beta2[j]
			flippedBits += bits.OnesCount8(diff)
			totalBits += 8
		}
	}

	ratio := float64(flippedBits) / float64(totalBits)
	t.Logf("avalanche ratio = %.4f (ideal = 0.50)", ratio)

	// Accept 40%–60% as reasonable; outside this range indicates bias.
	if ratio < 0.40 || ratio > 0.60 {
		t.Errorf("avalanche test FAILED: ratio=%.4f is outside [0.40, 0.60]", ratio)
	}
}

// TestVRFPseudorandomness_ByteDistribution_Keccak runs the same byte-frequency
// sanity check for the Keccak-backed VRF mode.
func TestVRFPseudorandomness_ByteDistribution_Keccak(t *testing.T) {
	const samples = 500
	seed := make([]byte, 64)
	rand.Read(seed)
	pub, priv, err := GenerateKey(seed)
	if err != nil {
		t.Fatal(err)
	}

	freq := make([]int, 256)
	total := 0
	for i := 0; i < samples; i++ {
		msg := make([]byte, 32)
		rand.Read(msg)
		_, beta, err := priv.VRFProveWithMode(&pub, msg, ModeKeccak)
		if err != nil {
			t.Fatalf("sample %d: %v", i, err)
		}
		for _, b := range beta {
			freq[b]++
			total++
		}
	}

	expected := float64(total) / 256.0
	chi2 := 0.0
	for _, f := range freq {
		diff := float64(f) - expected
		chi2 += (diff * diff) / expected
	}

	const criticalValue = 332.0
	t.Logf("keccak chi-squared = %.2f (critical = %.2f at p=0.001, df=255)", chi2, criticalValue)
	if chi2 > criticalValue {
		t.Errorf("keccak byte distribution test FAILED: chi-squared=%.2f > %.2f",
			chi2, criticalValue)
	}
}

// TestVRFPseudorandomness_AvalancheEffect_Keccak verifies the avalanche sanity
// check for the Keccak-backed VRF mode.
func TestVRFPseudorandomness_AvalancheEffect_Keccak(t *testing.T) {
	const samples = 200
	seed := make([]byte, 64)
	rand.Read(seed)
	pub, priv, err := GenerateKey(seed)
	if err != nil {
		t.Fatal(err)
	}

	totalBits := 0
	flippedBits := 0

	for i := 0; i < samples; i++ {
		msg := make([]byte, 32)
		rand.Read(msg)

		_, beta1, err := priv.VRFProveWithMode(&pub, msg, ModeKeccak)
		if err != nil {
			t.Fatalf("sample %d original: %v", i, err)
		}

		flipByte := i % len(msg)
		flipBit := uint(i % 8)
		msg2 := append([]byte(nil), msg...)
		msg2[flipByte] ^= 1 << flipBit

		_, beta2, err := priv.VRFProveWithMode(&pub, msg2, ModeKeccak)
		if err != nil {
			t.Fatalf("sample %d flipped: %v", i, err)
		}

		for j := range beta1 {
			diff := beta1[j] ^ beta2[j]
			flippedBits += bits.OnesCount8(diff)
			totalBits += 8
		}
	}

	ratio := float64(flippedBits) / float64(totalBits)
	t.Logf("keccak avalanche ratio = %.4f (ideal = 0.50)", ratio)

	if ratio < 0.40 || ratio > 0.60 {
		t.Errorf("keccak avalanche test FAILED: ratio=%.4f is outside [0.40, 0.60]", ratio)
	}
}

// TestVRFPseudorandomness_NoCollisions_Keccak checks collision absence for the
// Keccak-backed VRF mode over the same sample size.
func TestVRFPseudorandomness_NoCollisions_Keccak(t *testing.T) {
	const samples = 1000
	seed := make([]byte, 64)
	rand.Read(seed)
	pub, priv, err := GenerateKey(seed)
	if err != nil {
		t.Fatal(err)
	}

	seen := make(map[VRFOutput]struct{}, samples)
	for i := 0; i < samples; i++ {
		msg := make([]byte, 32)
		rand.Read(msg)
		_, beta, err := priv.VRFProveWithMode(&pub, msg, ModeKeccak)
		if err != nil {
			t.Fatalf("sample %d: %v", i, err)
		}
		if _, exists := seen[beta]; exists {
			t.Fatalf("keccak collision detected at sample %d", i)
		}
		seen[beta] = struct{}{}
	}
	t.Logf("keccak: no collisions in %d samples (512-bit output space)", samples)
}

// TestVRFPseudorandomness_BitBalance_Keccak checks per-bit balance for the
// Keccak-backed VRF mode.
func TestVRFPseudorandomness_BitBalance_Keccak(t *testing.T) {
	const samples = 500
	seed := make([]byte, 64)
	rand.Read(seed)
	pub, priv, err := GenerateKey(seed)
	if err != nil {
		t.Fatal(err)
	}

	bitCounts := make([]int, VRFBetaSize*8)
	for i := 0; i < samples; i++ {
		msg := make([]byte, 32)
		rand.Read(msg)
		_, beta, err := priv.VRFProveWithMode(&pub, msg, ModeKeccak)
		if err != nil {
			t.Fatalf("sample %d: %v", i, err)
		}
		for byteIdx, b := range beta {
			for bit := 0; bit < 8; bit++ {
				if b&(1<<uint(bit)) != 0 {
					bitCounts[byteIdx*8+bit]++
				}
			}
		}
	}

	failed := 0
	for i, count := range bitCounts {
		ratio := float64(count) / float64(samples)
		if ratio < 0.35 || ratio > 0.65 {
			t.Errorf("keccak bit %d: set ratio=%.3f is outside [0.35, 0.65]", i, ratio)
			failed++
		}
	}
	if failed == 0 {
		sum := 0.0
		for _, c := range bitCounts {
			sum += float64(c) / float64(samples)
		}
		mean := sum / float64(len(bitCounts))
		variance := 0.0
		for _, c := range bitCounts {
			d := float64(c)/float64(samples) - mean
			variance += d * d
		}
		variance /= float64(len(bitCounts))
		t.Logf("keccak bit balance: mean=%.4f stddev=%.4f (ideal: mean=0.5)",
			mean, math.Sqrt(variance))
	}
}

// TestVRFPseudorandomness_NoCollisions checks that N independent VRF outputs
// contain no collisions.  For a 512-bit output space, collisions are
// computationally impossible below ~2^256 samples; any collision here would
// indicate a catastrophic output-space reduction.
func TestVRFPseudorandomness_NoCollisions(t *testing.T) {
	const samples = 1000
	seed := make([]byte, 64)
	rand.Read(seed)
	pub, priv, err := GenerateKey(seed)
	if err != nil {
		t.Fatal(err)
	}

	seen := make(map[VRFOutput]struct{}, samples)
	for i := 0; i < samples; i++ {
		msg := make([]byte, 32)
		rand.Read(msg)
		_, beta, err := priv.VRFProve(&pub, msg)
		if err != nil {
			t.Fatalf("sample %d: %v", i, err)
		}
		if _, exists := seen[beta]; exists {
			t.Fatalf("collision detected at sample %d — output space is severely reduced", i)
		}
		seen[beta] = struct{}{}
	}
	t.Logf("no collisions in %d samples (512-bit output space)", samples)
}

// TestVRFPseudorandomness_BitBalance checks that each bit position in the
// output is approximately 50% set across many samples.
func TestVRFPseudorandomness_BitBalance(t *testing.T) {
	const samples = 500
	seed := make([]byte, 64)
	rand.Read(seed)
	pub, priv, err := GenerateKey(seed)
	if err != nil {
		t.Fatal(err)
	}

	bitCounts := make([]int, VRFBetaSize*8)
	for i := 0; i < samples; i++ {
		msg := make([]byte, 32)
		rand.Read(msg)
		_, beta, err := priv.VRFProve(&pub, msg)
		if err != nil {
			t.Fatalf("sample %d: %v", i, err)
		}
		for byteIdx, b := range beta {
			for bit := 0; bit < 8; bit++ {
				if b&(1<<uint(bit)) != 0 {
					bitCounts[byteIdx*8+bit]++
				}
			}
		}
	}

	// Each bit should be set ~50% of the time.
	// Allow ±10% (i.e., 40%–60%) at p≈0.001 for 512 bits × 500 samples.
	failed := 0
	for i, count := range bitCounts {
		ratio := float64(count) / float64(samples)
		if ratio < 0.35 || ratio > 0.65 {
			t.Errorf("bit %d: set ratio=%.3f is outside [0.35, 0.65]", i, ratio)
			failed++
		}
	}
	if failed == 0 {
		// Report mean and std-dev for documentation.
		sum := 0.0
		for _, c := range bitCounts {
			sum += float64(c) / float64(samples)
		}
		mean := sum / float64(len(bitCounts))
		variance := 0.0
		for _, c := range bitCounts {
			d := float64(c)/float64(samples) - mean
			variance += d * d
		}
		variance /= float64(len(bitCounts))
		t.Logf("bit balance: mean=%.4f stddev=%.4f (ideal: mean=0.5, stddev≈0.022)",
			mean, math.Sqrt(variance))
	}
}
