package falcon

import (
	"crypto/sha512"
	"fmt"
)

var (
	ErrVRFProveFail       = fmt.Errorf("falcon vrf prove failed")
	ErrVRFVerifyFail      = fmt.Errorf("falcon vrf verify failed")
	ErrVRFProofToHashFail = fmt.Errorf("falcon vrf proof-to-hash failed")
)

const (
	VRFBetaSize = sha512.Size
)

type VRFProof = CompressedSignature
type VRFOutput [VRFBetaSize]byte

var (
	vrfDomainProve = []byte("FALCON-VRF-PROVE-v1")
	vrfDomainBeta  = []byte("FALCON-VRF-BETA-v1")
)

func makeVRFProveTranscript(pk *PublicKey, msg []byte) (out [sha512.Size]byte) {
	h := sha512.New()
	_, _ = h.Write(vrfDomainProve)
	_, _ = h.Write(pk[:])
	_, _ = h.Write(msg)

	sum := h.Sum(nil)
	copy(out[:], sum)
	return
}

func VRFProofToHash(pk *PublicKey, proof VRFProof, msg []byte) (VRFOutput, error) {
	var beta VRFOutput

	if pk == nil {
		return beta, fmt.Errorf("nil public key: %w", ErrVRFProofToHashFail)
	}
	if len(proof) == 0 {
		return beta, fmt.Errorf("empty proof: %w", ErrVRFProofToHashFail)
	}

	h := sha512.New()
	_, _ = h.Write(vrfDomainBeta)
	_, _ = h.Write(pk[:])
	_, _ = h.Write(msg)
	_, _ = h.Write(proof)

	sum := h.Sum(nil)
	copy(beta[:], sum)
	return beta, nil
}

func (sk *PrivateKey) VRFProve(pk *PublicKey, msg []byte) (VRFProof, VRFOutput, error) {
	return sk.VRFProveWithMode(pk, msg, ModeSHAKE)
}

// VRFProveWithMode computes a proof and beta using the selected backend.
func (sk *PrivateKey) VRFProveWithMode(pk *PublicKey, msg []byte, mode Mode) (VRFProof, VRFOutput, error) {
	var zero VRFOutput

	if sk == nil {
		return nil, zero, fmt.Errorf("nil private key: %w", ErrVRFProveFail)
	}
	if pk == nil {
		return nil, zero, fmt.Errorf("nil public key: %w", ErrVRFProveFail)
	}

	transcript := makeVRFProveTranscript(pk, msg)

	proof, err := sk.SignCompressedWithMode(transcript[:], mode)
	if err != nil {
		return nil, zero, fmt.Errorf("sign transcript: %w", err)
	}

	beta, err := VRFProofToHash(pk, proof, msg)
	if err != nil {
		return nil, zero, fmt.Errorf("derive beta: %w", err)
	}

	return proof, beta, nil
}

func (pk *PublicKey) VRFVerify(proof VRFProof, msg []byte) (VRFOutput, error) {
	return pk.VRFVerifyWithMode(proof, msg, ModeSHAKE)
}

// VRFVerifyWithMode verifies a VRF proof using the selected backend.
func (pk *PublicKey) VRFVerifyWithMode(proof VRFProof, msg []byte, mode Mode) (VRFOutput, error) {
	var zero VRFOutput

	if pk == nil {
		return zero, fmt.Errorf("nil public key: %w", ErrVRFVerifyFail)
	}
	if len(proof) == 0 {
		return zero, fmt.Errorf("empty proof: %w", ErrVRFVerifyFail)
	}

	transcript := makeVRFProveTranscript(pk, msg)

	if err := pk.VerifyWithMode(proof, transcript[:], mode); err != nil {
		return zero, fmt.Errorf("verify transcript signature: %w", err)
	}

	beta, err := VRFProofToHash(pk, proof, msg)
	if err != nil {
		return zero, fmt.Errorf("derive beta: %w", err)
	}

	return beta, nil
}