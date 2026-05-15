#!/bin/bash
set -euxo pipefail
exec > >(tee /var/log/user-data.log | tee /dev/console) 2>&1

echo "DFVRF_AWS_DETKAT_BEGIN"
date -u +"utc=%Y-%m-%dT%H:%M:%SZ"
uname -a
cat /etc/os-release || true
lscpu | egrep 'Architecture|Model name|Vendor ID|CPU\(s\)|Byte Order' || true

dnf -y update
dnf -y install git gcc gcc-c++ make tar gzip

case "$(uname -m)" in
  x86_64) GOARCH_DL="amd64" ;;
  aarch64) GOARCH_DL="arm64" ;;
  *) echo "unsupported arch $(uname -m)"; exit 1 ;;
esac

curl -fsSL "https://go.dev/dl/go1.25.5.linux-${GOARCH_DL}.tar.gz" -o /tmp/go.tgz
rm -rf /usr/local/go
tar -C /usr/local -xzf /tmp/go.tgz
export PATH="/usr/local/go/bin:${PATH}"
export GOTELEMETRY=off
export HOME=/root
export GOCACHE=/tmp/gocache
mkdir -p "$GOCACHE"
go version

cd /tmp
git clone --depth 1 https://github.com/smin-k/DF-VRF.git
cd DF-VRF
mkdir -p cmd/detkat
cat > cmd/detkat/main.go <<'EOF_DETKAT'
package main

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log"
	"os"

	falcon "DF_VRF/crypto"
)

type vector struct {
	Name            string `json:"name"`
	SeedHex         string `json:"seed_hex"`
	MessageHex      string `json:"message_hex"`
	PublicKeyHex    string `json:"public_key_hex"`
	TranscriptHex   string `json:"transcript_hex"`
	SignatureShake  string `json:"signature_shake_hex"`
	SignatureKeccak string `json:"signature_keccak_hex"`
	VRFProofShake   string `json:"vrf_proof_shake_hex"`
	VRFBetaShake    string `json:"vrf_beta_shake_hex"`
	VRFProofKeccak  string `json:"vrf_proof_keccak_hex"`
	VRFBetaKeccak   string `json:"vrf_beta_keccak_hex"`
	VectorDigestHex string `json:"vector_digest_hex"`
}

func main() {
	inputs := []struct {
		name string
		seed []byte
		msg  []byte
	}{
		{"empty-message", []byte("df-vrf-detkat-seed-000"), nil},
		{"short-message", []byte("df-vrf-detkat-seed-001"), []byte("DF-VRF deterministic KAT 1")},
		{"binary-message", []byte("df-vrf-detkat-seed-002"), []byte{0x00, 0x01, 0x02, 0x7f, 0x80, 0xfe, 0xff}},
		{"long-message", []byte("df-vrf-detkat-seed-003"), []byte("DF-VRF deterministic KAT with a longer message used to compare Windows and Linux container outputs byte-for-byte.")},
	}
	vectors := make([]vector, 0, len(inputs))
	for _, in := range inputs {
		v, err := makeVector(in.name, in.seed, in.msg)
		if err != nil {
			log.Fatalf("%s: %v", in.name, err)
		}
		vectors = append(vectors, v)
	}
	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")
	if err := enc.Encode(vectors); err != nil {
		log.Fatal(err)
	}
}

func makeVector(name string, seed, msg []byte) (vector, error) {
	pub, priv, err := falcon.GenerateKey(seed)
	if err != nil {
		return vector{}, fmt.Errorf("generate key: %w", err)
	}
	sigShake, err := priv.SignCompressed(msg)
	if err != nil {
		return vector{}, fmt.Errorf("sign shake: %w", err)
	}
	if err := pub.Verify(sigShake, msg); err != nil {
		return vector{}, fmt.Errorf("verify shake: %w", err)
	}
	sigKeccak, err := priv.SignCompressedWithMode(msg, falcon.ModeKeccak)
	if err != nil {
		return vector{}, fmt.Errorf("sign keccak: %w", err)
	}
	if err := pub.VerifyWithMode(sigKeccak, msg, falcon.ModeKeccak); err != nil {
		return vector{}, fmt.Errorf("verify keccak: %w", err)
	}
	proofShake, betaShake, err := priv.VRFProve(&pub, msg)
	if err != nil {
		return vector{}, fmt.Errorf("vrf prove shake: %w", err)
	}
	if beta, err := pub.VRFVerify(proofShake, msg); err != nil {
		return vector{}, fmt.Errorf("vrf verify shake: %w", err)
	} else if beta != betaShake {
		return vector{}, fmt.Errorf("vrf beta mismatch shake")
	}
	proofKeccak, betaKeccak, err := priv.VRFProveWithMode(&pub, msg, falcon.ModeKeccak)
	if err != nil {
		return vector{}, fmt.Errorf("vrf prove keccak: %w", err)
	}
	if beta, err := pub.VRFVerifyWithMode(proofKeccak, msg, falcon.ModeKeccak); err != nil {
		return vector{}, fmt.Errorf("vrf verify keccak: %w", err)
	} else if beta != betaKeccak {
		return vector{}, fmt.Errorf("vrf beta mismatch keccak")
	}
	transcript := falcon.MakeVRFTranscript(&pub, msg)
	v := vector{
		Name:            name,
		SeedHex:         hex.EncodeToString(seed),
		MessageHex:      hex.EncodeToString(msg),
		PublicKeyHex:    hex.EncodeToString(pub[:]),
		TranscriptHex:   hex.EncodeToString(transcript[:]),
		SignatureShake:  hex.EncodeToString(sigShake),
		SignatureKeccak: hex.EncodeToString(sigKeccak),
		VRFProofShake:   hex.EncodeToString(proofShake),
		VRFBetaShake:    hex.EncodeToString(betaShake[:]),
		VRFProofKeccak:  hex.EncodeToString(proofKeccak),
		VRFBetaKeccak:   hex.EncodeToString(betaKeccak[:]),
	}
	v.VectorDigestHex = digestVector(v)
	return v, nil
}

func digestVector(v vector) string {
	h := sha256.New()
	for _, part := range []string{
		v.Name, v.SeedHex, v.MessageHex, v.PublicKeyHex, v.TranscriptHex,
		v.SignatureShake, v.SignatureKeccak, v.VRFProofShake, v.VRFBetaShake,
		v.VRFProofKeccak, v.VRFBetaKeccak,
	} {
		_, _ = h.Write([]byte(part))
		_, _ = h.Write([]byte{0})
	}
	return hex.EncodeToString(h.Sum(nil))
}
EOF_DETKAT

go run ./cmd/detkat > /tmp/detkat.json
sha256sum /tmp/detkat.json
echo "DFVRF_DETKAT_JSON_BEGIN"
cat /tmp/detkat.json
echo "DFVRF_DETKAT_JSON_END"

go test ./crypto -run "TestFalconVRFDeterministic|TestFalconVRFKeccakMode|TestVRFUniqueness_Determinism|TestVRFUniqueness_Determinism_Keccak" -v
echo "DFVRF_AWS_DETKAT_DONE"
sleep 600
shutdown -h now
