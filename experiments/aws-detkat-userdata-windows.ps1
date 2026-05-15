<powershell>
$ErrorActionPreference = "Stop"
$ProgressPreference = "SilentlyContinue"

function Log($Message) {
    $line = "$(Get-Date -AsUTC -Format o) $Message"
    Write-Output $line
    Add-Content -Path "C:\dfvrf-detkat.log" -Value $line
}

Log "DFVRF_AWS_WINDOWS_DETKAT_BEGIN"
Log "os=$([System.Environment]::OSVersion.VersionString)"
Log "arch=$([System.Runtime.InteropServices.RuntimeInformation]::OSArchitecture)"
Get-CimInstance Win32_Processor |
    Select-Object Name, Manufacturer, NumberOfCores, NumberOfLogicalProcessors |
    Format-List |
    Out-String |
    ForEach-Object { Log $_ }

$env:HOME = "C:\Users\Administrator"
$env:GOCACHE = "C:\gocache"
New-Item -ItemType Directory -Force -Path $env:GOCACHE | Out-Null
New-Item -ItemType Directory -Force -Path "C:\dfvrf" | Out-Null

$goZip = "C:\dfvrf\go.zip"
$repoZip = "C:\dfvrf\df-vrf.zip"
Invoke-WebRequest -Uri "https://go.dev/dl/go1.25.5.windows-amd64.zip" -OutFile $goZip
Expand-Archive -Path $goZip -DestinationPath "C:\dfvrf" -Force
$env:Path = "C:\dfvrf\go\bin;$env:Path"
go version | ForEach-Object { Log $_ }

Invoke-WebRequest -Uri "https://github.com/smin-k/DF-VRF/archive/refs/heads/main.zip" -OutFile $repoZip
Expand-Archive -Path $repoZip -DestinationPath "C:\dfvrf" -Force
Set-Location "C:\dfvrf\DF-VRF-main"
New-Item -ItemType Directory -Force -Path "cmd\detkat" | Out-Null

@'
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
'@ | Set-Content -Path "cmd\detkat\main.go" -Encoding UTF8

go run ./cmd/detkat *> C:\dfvrf\detkat.json
Get-FileHash C:\dfvrf\detkat.json -Algorithm SHA256 | Format-List | Out-String | ForEach-Object { Log $_ }
Log "DFVRF_DETKAT_JSON_BEGIN"
Get-Content C:\dfvrf\detkat.json | ForEach-Object { Log $_ }
Log "DFVRF_DETKAT_JSON_END"

go test ./crypto -run "TestFalconVRFDeterministic|TestFalconVRFKeccakMode|TestVRFUniqueness_Determinism|TestVRFUniqueness_Determinism_Keccak" -v *> C:\dfvrf\go-test.log
Get-Content C:\dfvrf\go-test.log | ForEach-Object { Log $_ }
Log "DFVRF_AWS_WINDOWS_DETKAT_DONE"
Stop-Computer -Force
</powershell>
