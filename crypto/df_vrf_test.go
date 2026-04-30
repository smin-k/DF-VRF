package falcon

import (
	"bytes"
	"crypto/rand"
	"testing"
)

func TestFalconVRFRoundTrip(t *testing.T) {
	seed := make([]byte, 64)
	rand.Read(seed)

	pub, priv, err := GenerateKey(seed)
	if err != nil {
		t.Fatalf("failed to generate keys. err message: %s", err)
	}

	msg := make([]byte, 256)
	rand.Read(msg)

	proof, beta1, err := priv.VRFProve(&pub, msg)
	if err != nil {
		t.Fatalf("failed to prove vrf. err message: %s", err)
	}

	if len(proof) == 0 {
		t.Fatalf("vrf proof is empty")
	}

	beta2, err := pub.VRFVerify(proof, msg)
	if err != nil {
		t.Fatalf("failed to verify vrf proof. err message: %s", err)
	}

	beta3, err := VRFProofToHash(&pub, proof, msg)
	if err != nil {
		t.Fatalf("failed to derive beta from proof. err message: %s", err)
	}

	if beta1 != beta2 {
		t.Fatalf("beta mismatch between prove and verify")
	}
	if beta1 != beta3 {
		t.Fatalf("beta mismatch between prove and proof-to-hash")
	}
}

func TestFalconVRFDeterministic(t *testing.T) {
	seed := make([]byte, 64)
	rand.Read(seed)

	pub, priv, err := GenerateKey(seed)
	if err != nil {
		t.Fatalf("failed to generate keys. err message: %s", err)
	}

	msg := make([]byte, 256)
	rand.Read(msg)

	proof1, beta1, err := priv.VRFProve(&pub, msg)
	if err != nil {
		t.Fatalf("first vrf prove failed. err message: %s", err)
	}

	proof2, beta2, err := priv.VRFProve(&pub, msg)
	if err != nil {
		t.Fatalf("second vrf prove failed. err message: %s", err)
	}

	if !bytes.Equal(proof1, proof2) {
		t.Fatalf("deterministic vrf produced different proofs")
	}

	if beta1 != beta2 {
		t.Fatalf("deterministic vrf produced different betas")
	}
}

func TestFalconVRFTamperedMessage(t *testing.T) {
	seed := make([]byte, 64)
	rand.Read(seed)

	pub, priv, err := GenerateKey(seed)
	if err != nil {
		t.Fatalf("failed to generate keys. err message: %s", err)
	}

	msg := make([]byte, 256)
	rand.Read(msg)

	proof, _, err := priv.VRFProve(&pub, msg)
	if err != nil {
		t.Fatalf("failed to prove vrf. err message: %s", err)
	}

	badMsg := append([]byte(nil), msg...)
	badMsg[0] ^= 0x01

	_, err = pub.VRFVerify(proof, badMsg)
	if err == nil {
		t.Fatalf("vrf verification succeeded on tampered message; should have failed")
	}
}

func TestFalconVRFTamperedProof(t *testing.T) {
	seed := make([]byte, 64)
	rand.Read(seed)

	pub, priv, err := GenerateKey(seed)
	if err != nil {
		t.Fatalf("failed to generate keys. err message: %s", err)
	}

	msg := make([]byte, 256)
	rand.Read(msg)

	proof, _, err := priv.VRFProve(&pub, msg)
	if err != nil {
		t.Fatalf("failed to prove vrf. err message: %s", err)
	}

	badProof := append(CompressedSignature(nil), proof...)
	badProof[len(badProof)-1] ^= 0x01

	_, err = pub.VRFVerify(badProof, msg)
	if err == nil {
		t.Fatalf("vrf verification succeeded on tampered proof; should have failed")
	}
}

func TestFalconVRFNilAndEmptyMessage(t *testing.T) {
	seed := make([]byte, 64)
	rand.Read(seed)

	pub, priv, err := GenerateKey(seed)
	if err != nil {
		t.Fatalf("failed to generate keys. err message: %s", err)
	}

	proofNil, betaNil, err := priv.VRFProve(&pub, nil)
	if err != nil {
		t.Fatalf("failed to prove vrf on nil message. err message: %s", err)
	}

	betaNilVerify, err := pub.VRFVerify(proofNil, nil)
	if err != nil {
		t.Fatalf("failed to verify vrf on nil message. err message: %s", err)
	}

	proofEmpty, betaEmpty, err := priv.VRFProve(&pub, []byte{})
	if err != nil {
		t.Fatalf("failed to prove vrf on empty message. err message: %s", err)
	}

	betaEmptyVerify, err := pub.VRFVerify(proofEmpty, []byte{})
	if err != nil {
		t.Fatalf("failed to verify vrf on empty message. err message: %s", err)
	}

	if !bytes.Equal(proofNil, proofEmpty) {
		t.Fatalf("nil and empty message should produce identical deterministic vrf proofs")
	}

	if betaNil != betaNilVerify {
		t.Fatalf("nil-message beta mismatch between prove and verify")
	}

	if betaEmpty != betaEmptyVerify {
		t.Fatalf("empty-message beta mismatch between prove and verify")
	}

	if betaNil != betaEmpty {
		t.Fatalf("nil and empty message should produce identical vrf outputs")
	}
}

func TestFalconVRFKeccakMode(t *testing.T) {
	seed := []byte("keccak-vrf-seed")
	msg := []byte("keccak-vrf-message")

	pub, priv, err := GenerateKey(seed)
	if err != nil {
		t.Fatalf("failed to generate keys: %s", err)
	}

	proof1, beta1, err := priv.VRFProveWithMode(&pub, msg, ModeKeccak)
	if err != nil {
		t.Fatalf("failed to prove vrf in keccak mode: %s", err)
	}

	beta2, err := pub.VRFVerifyWithMode(proof1, msg, ModeKeccak)
	if err != nil {
		t.Fatalf("failed to verify vrf in keccak mode: %s", err)
	}

	proof2, beta3, err := priv.VRFProveWithMode(&pub, msg, ModeKeccak)
	if err != nil {
		t.Fatalf("failed to reprove vrf in keccak mode: %s", err)
	}

	if !bytes.Equal(proof1, proof2) {
		t.Fatalf("keccak vrf proof is not deterministic")
	}
	if beta1 != beta2 {
		t.Fatalf("beta mismatch between keccak prove and verify")
	}
	if beta1 != beta3 {
		t.Fatalf("beta mismatch between repeated keccak proofs")
	}

	badMsg := append([]byte(nil), msg...)
	badMsg[0] ^= 0x01
	if _, err := pub.VRFVerifyWithMode(proof1, badMsg, ModeKeccak); err == nil {
		t.Fatalf("keccak vrf verification succeeded on tampered message; should have failed")
	}
}