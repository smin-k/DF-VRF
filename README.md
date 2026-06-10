# DF-VRF: Post-Quantum VRF for Ethereum

Deterministic Falcon-512-based Verifiable Random Function (VRF) with practical on-chain verification on EVM.

**Key contribution:** First practical Falcon-based VRF with on-chain Solidity verifier, combining FALCON_DET determinism, ETHFALCON's NTT-domain verification, and Keccak256-based hash-to-point for EVM efficiency.

## Features

- **Deterministic signing:** FALCON_DET512 eliminates randomness; same (sk, msg) -> same proof.
- **Two hash-to-point modes:**
  - **SHAKE256** (NIST-compliant): 4,051,960 gas on Ethereum
  - **Keccak256** (EVM-optimized): 1,495,903 gas on Ethereum -- 63% cheaper via native precompile
- **Compact proofs:** Average 618 B (SHAKE) or 657 B (Keccak), vs 5 KB for LB-VRF or 12 KB for LaV
- **Fast off-chain:** Prove 3.35 ms, Verify 0.023 ms (SHAKE256)
- **Security properties tested:** Determinism, injectivity, pseudorandomness stats, no collisions

## Cross-Platform Determinism Results

DF-VRF includes deterministic known-answer tests (KATs) for Falcon signatures and VRF proofs.
The KAT generator is in `cmd/detkat`, and the GitHub Actions workflow is in
`.github/workflows/detkat.yml`.

The experiment fixes four `(seed, message)` inputs and records:

- public key
- VRF transcript
- deterministic Falcon signature in SHAKE mode
- deterministic Falcon signature in Keccak mode
- VRF proof and beta in SHAKE mode
- VRF proof and beta in Keccak mode
- a `vector_digest_hex` over the semantic fields above

### Verified Environments

| Environment | OS / runner | Architecture | CPU / runner detail | Result |
|-------------|-------------|--------------|---------------------|--------|
| Local Windows | Windows native | x86_64 | AMD Ryzen 5 5600X | same vector digests |
| Docker Linux | `golang:1.25-bookworm` | x86_64 | same local host | same vector digests |
| AWS Linux x86 | Amazon Linux 2023 | x86_64 | Intel Xeon Platinum 8175M | same vector digests; tests PASS |
| AWS Linux ARM | Amazon Linux 2023 | arm64 | AWS Graviton2 / Neoverse-N1 | same vector digests; tests PASS |
| GitHub macOS Intel | `macos-15-intel` | x86_64 | GitHub-hosted Intel macOS runner | same vector digests; tests PASS |
| GitHub macOS ARM | `macos-15` | arm64 | Apple M1 virtual runner | same vector digests; tests PASS |

Successful macOS workflow run:
https://github.com/smin-k/DF-VRF/actions/runs/25904612323

### Reference Vector Digests

All verified platforms produced the same four semantic vector digests:

```text
75a9a486600b2195bf153d0f4da91edfbdcec6df8c87b9fa4fc371808d3bb1db
f0cc248d79ba60586cb94f46b0e0346b01b707672f5dfc8c4646037fcbdf8053
a022bbb94b4a85f9936add1157dc926cd09cec0862012d45884d407239913a73
87ebb668cf651b80fdf5944584e172a2eb326e6a4f32799861d2c9f26ebe17b3
```

The macOS Intel and macOS ARM JSON artifacts are byte-for-byte identical:

```text
SHA256(detkat_macos-intel.json) = 0519704fc00f209a528115c2677b651904ffbc01861f832736bf32a932817657
SHA256(detkat_macos-arm64.json) = 0519704fc00f209a528115c2677b651904ffbc01861f832736bf32a932817657
```

The Windows and Docker Linux reference files were generated through PowerShell
redirection, so the paper-facing comparison uses the semantic vector digests
rather than raw file bytes.

### Result Artifacts

| File | Description |
|------|-------------|
| `experiments/detkat_windows_current.json` | Windows native KAT output |
| `experiments/detkat_linux_container_current.json` | Docker Linux x86_64 KAT output |
| `experiments/detkat_macos-intel.json` | GitHub Actions macOS Intel KAT artifact |
| `experiments/detkat_macos-arm64.json` | GitHub Actions macOS ARM64 KAT artifact |
| `experiments/aws_x86_console_r3.txt` | AWS Linux x86_64 console log with KAT and PASS output |
| `experiments/aws_arm64_console_r3.txt` | AWS Linux ARM64 console log with KAT and PASS output |
| `experiments/aws-detkat-userdata.sh` | AWS Linux user-data script used for EC2 experiments |
| `experiments/aws-detkat-userdata-windows.ps1` | Windows EC2 user-data draft; retained for reproducibility notes |

Reproduce locally:

```bash
go run ./cmd/detkat > detkat.json
grep '"vector_digest_hex"' detkat.json
go test ./crypto -run 'TestFalconVRFDeterministic|TestFalconVRFKeccakMode|TestVRFUniqueness_Determinism|TestVRFUniqueness_Determinism_Keccak' -v
```

## Directory Layout

- `crypto/`: C implementation (Falcon-512 det, Keccak support) + Go bindings for VRF API
  - `falcon.go` -- public/private key types, signing, VRF Prove/Verify
  - `df_vrf.go` -- VRF transcript and output derivation
  - `ntt_helper.c` -- NTT computation and Keccak proof extraction
  - `*_test.go` -- unit tests + security property tests
- `contracts/`: Solidity verification contracts
  - `DFVRF_vrf_falcon.sol` -- SHAKE256 mode verifier
  - `DFVRF_vrf_falcon_evm.sol` -- Keccak256 mode verifier (gas-optimized)
  - `DFVRF_vrf_epervier.sol` -- Epervier-based variants
- `cmd/vrfjson/` -- Go CLI exporting test fixtures (for Hardhat)
- `cmd/vrfexp/` -- experimental VRF sample CSV generator
- `cmd/detkat/` -- deterministic KAT generator for cross-platform reproducibility
- `.github/workflows/detkat.yml` -- macOS Intel/ARM deterministic KAT workflow
- `experiments/` -- cross-platform KAT outputs, AWS logs, and experiment scripts
- `test/` -- Hardhat/Mocha E2E tests with gas benchmarks

## Performance Metrics

### Off-chain (Go, AMD Ryzen 5 5600X)

| Operation | SHAKE256 | Keccak256 |
|-----------|----------|-----------|
| KeyGen | 11.4 ms | 11.4 ms |
| Prove | 3.35 ms | 3.37 ms |
| Verify | 0.023 ms | 0.043 ms |

### Proof Sizes (1,000 random samples)

| Mode | Min | Avg | Max | Public Key |
|------|-----|-----|-----|------------|
| SHAKE256 | 610 B | **618 B** | 626 B | 897 B |
| Keccak256 | 651 B | **657 B** | 666 B | 897 B |

### On-chain Gas (Hardhat EVM)

The main DF-VRF verifier cost is Falcon verification plus hash-to-point. The
VRF output itself is derived as `beta = H(domain || pk || msg || proof)`, so
ProofToHash is hash-level work rather than an additional group-relation check.

| Verifier / baseline | Model | Gas cost |
|---------------------|-------|----------|
| DF-VRF SHAKE256 + `ntth` witness | NIST hash-to-point | 4,051,960 |
| DF-VRF Keccak256 + `ntth` witness | EVM-optimized hash-to-point | **1,495,903** |
| Witnet ECVRF full `verify` | Solidity secp256k1 VRF verification | 1,615,423 |
| Witnet ECVRF `fastVerify` | `ecrecover`-assisted + extra witness | 110,077 |
| ECDSA `ecrecover` wrapper | native precompile-assisted signature recovery | 26,988 |
| ECDSA without `ecrecover` | Solidity secp256k1 arithmetic | 1,048,404 |

ECVRF full verification is dominated by elliptic-curve relation checks. In the
Witnet implementation, the two equations `U = sG - cY` and `V = sH - cGamma`
cost about 788K gas each. By contrast, DF-VRF reduces verifiability to
deterministic Falcon verification, and derives the VRF output by hashing the
canonical proof transcript.

ECVRF `fastVerify` is much cheaper, but it is a different model: the verifier
receives additional EC witness points and uses the EVM `ecrecover` precompile.
Computing those fast-verify parameters on-chain costs about 1,583,717 gas.

### Gas Decomposition: Hash-to-Point vs NTT Witness

The final verifier combines two independent optimizations: replacing SHAKE256
hash-to-point with EVM-native Keccak256, and passing `ntth = NTT(h)` as a witness
instead of computing the public-key NTT on-chain.

| Variant | Hash-to-point | Public key input | Verify gas |
|---------|---------------|------------------|------------|
| SHAKE verifier with on-chain NTT(h) | SHAKE256 | compact `h`; computes `NTT(h)` on-chain | 4,623,461 |
| SHAKE verifier with ntth witness | SHAKE256 | `ntth = NTT(h)` witness | 4,051,960 |
| Keccak verifier with on-chain NTT(h) | Keccak256 | compact `h`; computes `NTT(h)` on-chain | 2,053,191 |
| Keccak verifier with ntth witness | Keccak256 | `ntth = NTT(h)` witness | **1,495,903** |

Passing `ntth` instead of computing `NTT(h)` on-chain saves **571,501 gas**
(**12.36%**) in the SHAKE verifier and **557,288 gas** (**27.14%**) in the Keccak
verifier. Replacing SHAKE256 hash-to-point with EVM-native Keccak256 saves about
2.56M gas when the same `ntth` witness design is used.

### Classical Baseline Decomposition

The repository also includes ECDSA and ECVRF gas baselines to make clear which
comparisons use native EVM support.

| Baseline | Gas | Interpretation |
|----------|-----|----------------|
| `ecrecover` precompile only | 3,000 | geth native precompile cost at address `0x01` |
| Minimal ECDSA wrapper | 26,988 | transaction-level Solidity call using `ecrecover` |
| Solidity secp256k1 ECDSA | 1,048,404 | no `ecrecover`; uses EVM field/curve arithmetic |
| Witnet ECVRF full `verify` | 1,615,423 | full secp256k1 VRF verification in Solidity |
| Witnet ECVRF `fastVerify` | 110,077 | extra witness + `ecrecover` shortcut |

For the Witnet ECVRF full verifier, the measured stage costs were:

| Stage | Gas |
|-------|-----|
| `hashToTryAndIncrement` | 58,987 |
| `ecMulSubMul` for `U = sG - cY` | 787,700 |
| `ecMulSubMul` for `V = sH - cGamma` | 789,824 |
| `hashPoints` | 31,340 |
| `gammaToHash` | 23,865 |

These measurements show that full ECVRF verification is dominated by the two
secp256k1 scalar-multiplication relations. DF-VRF's VRF-specific output
derivation is instead hash-level; its dominant on-chain cost is Falcon
verification.

## Comparison with Other Post-Quantum VRFs

| Scheme | Security | PK (B) | Proof (B) | Prove (ms) | Verify (ms) | On-chain |
|--------|----------|--------|-----------|------------|------------|----------|
| LB-VRF | Mod-SIS/LWE | 3,320 | ~5,000 | ~3 | ~1 | no |
| LaV | Mod-LWE | 6,420 | ~12,000 | n/a | n/a | no |
| X-VRF | Hash (XMSS) | ~2,000 | <=3,000 | n/a | n/a | partial |
| DeuringVRF | Isogeny | 224 | 226 | ~160 | ~18 | no |
| **DF-VRF** | **NTRU** | **897** | **618** | **3.35** | **0.023** | yes |

X-VRF's uniqueness was broken in 2024.

## Go Module

- Module path: `DF_VRF`
- Crypto engine import path: `DF_VRF/crypto`

## Quick Start (Go)

Build CLIs:

```bash
go build ./cmd/vrfjson
```

Run all Go tests (including security property tests):

```bash
go test ./crypto/ -v
```

Run specific test suites:

```bash
# VRF correctness and determinism
go test ./crypto -v -run TestFalconVRF

# Security property tests (uniqueness, pseudorandomness)
go test ./crypto -v -run "TestVRFUniqueness|TestVRFPseudorandomness"

# Benchmarks (KeyGen, Prove, Verify throughput)
go test ./crypto -bench=Benchmark -benchtime=5s

# Proof size distribution (over 1,000 samples)
go test ./crypto -v -run TestProofSizeDistribution
```

## Quick Start (Hardhat)

Install dependencies and compile contracts:

```bash
npm install
npm run compile
```

Run all Hardhat E2E tests (24 tests, ~30s):

```bash
npm test
```

Run gas benchmarks only:

```bash
npm test -- --grep "Gas benchmarks"
```

Run gas decomposition and classical baselines:

```bash
npm test -- --grep "Gas decomposition"
npm run baseline:ecdsa
npm run baseline:ecdsa:pure
npm run baseline:vrf
```

Generate test fixture from Go:

```bash
npm run vrf:export
# -> test/fixtures/vrf_sample.json
```

Deploy to local Hardhat node:

```bash
npx hardhat node          # terminal 1
npm run deploy:local      # terminal 2
```

## On-chain Verification Architecture

### Key design: NTT domain witness

To make on-chain verification feasible, DF-VRF passes the **NTT-domain representation of the public key (ntth = NTT(h))** as a witness rather than computing it on-chain.

**Workflow:**

1. **Off-chain (Go):** Generate VRF proof pi = signature(transcript)
2. **Off-chain:** Compute ntth = NTT(h) once per public key
3. **On-chain call:** `verify(transcript, salt, s2, ntth)`
4. **On-chain (Solidity):** 
   - Recover c = Falcon challenge from transcript
   - Compute s1 = INTT(NTT(s2) * ntth)
   - Check ||c - s1||² + ||s2||² < sigBound

**Cost reduction:** Avoiding on-chain public-key NTT saves 571,501 gas in the SHAKE verifier
(4,623,461 -> 4,051,960 gas) and 557,288 gas in the Keccak verifier
(2,053,191 -> 1,495,903 gas). The larger reduction from the SHAKE verifier is mostly due to
replacing SHAKE256 hash-to-point with EVM-native Keccak256.

**Trust model:** The ntth witness is trusted to be correct. In production, either:
- Verifier has registered ntth in an on-chain registry by its own computation
- Or: Application trusts a specific off-chain server (similar to beacon services)

### Implementation Status

| Component | Status |
|-----------|--------|
| Go VRF prove/verify (Falcon-512, deterministic) | complete |
| Keccak256 hash-to-point (Go) | complete |
| NTT computation (Go) | complete |
| DFVRF_vrf_falcon.sol (SHAKE256 verifier) | verified, 4M gas |
| DFVRF_vrf_falcon_evm.sol (Keccak256 verifier) | verified, 1.5M gas |
| DFVRF_vrf_epervier.sol (Epervier verifier) | compiles, untested |
| Security property tests | 9/9 passing |

## Cryptographic Parameters

| Parameter | Value |
|-----------|-------|
| **Signature algorithm** | Falcon-512 (deterministic mode, FALCON_DET512) |
| **Hardness assumption** | NTRU lattice problem (hard for quantum computers) |
| Polynomial degree | n = 512 |
| Modulus | q = 12,289 |
| logn | 9 |
| **Fixed salt (SHAKE mode)** | 40 bytes: `[0x00, 0x09, "FALCON_DET", 0x00×28]` |
| **Variable nonce (Keccak mode)** | 40 bytes, derived from proof header |
| **VRF transcript** | SHA-512(`"FALCON-VRF-PROVE-v1" || pk || msg`) |
| **VRF output beta** | SHA-512(`"FALCON-VRF-BETA-v1" || pk || msg || proof`) |
| **Polynomial packing** | 16 coefficients × 16 bits per uint256 word |
| **s2 / h word count** | 32 words (512 coefficients ÷ 16 per word) |

## Security Properties

DF-VRF satisfies the three standard VRF properties:

### 1. Correctness (Provability)
- **Tested:** `TestFalconVRFRoundTrip` -- Prove -> Verify always succeeds
- **Basis:** Falcon-512 signature correctness

### 2. Uniqueness
- **Tested:** `TestVRFUniqueness_Determinism` -- same (sk, msg) -> same proof
- **Tested:** `TestVRFUniqueness_DifferentKeys` -- different pk -> different output
- **Tested:** `TestVRFUniqueness_DifferentMessages` -- different msg -> different output
- **Tested:** `TestVRFUniqueness_ProofBinding` -- tampered proof != same output
- **Basis:** FALCON_DET determinism + Falcon unforgeability

### Malleability note

DF-VRF binds the output to the exact proof bytes:

```text
beta = SHA-512("FALCON-VRF-BETA-v1" || pk || msg || proof)
```

Thus, generated proofs are deterministic and proof-byte-bound. A modified proof
must either fail Falcon verification or produce a different beta. This is
different from claiming unconditional strong uniqueness for every possible
Falcon signature encoding: a second accepted proof for the same `(pk, msg)`
would amount to producing another valid Falcon signature for the fixed VRF
transcript. For on-chain use, the verifier should keep strict length and
canonical polynomial encoding checks to avoid encoding-level malleability.

### 3. Pseudorandomness (statistical)
- **Tested:** `TestVRFPseudorandomness_ByteDistribution` -- chi^2 = 247 (critical = 332)
- **Tested:** `TestVRFPseudorandomness_AvalancheEffect` -- 1-bit input change flips ~57% of output
- **Tested:** `TestVRFPseudorandomness_NoCollisions` -- 1,000 samples, 0 collisions
- **Tested:** `TestVRFPseudorandomness_BitBalance` -- bit balance mean = 0.501
- **Basis:** Falcon unforgeability + SHA-512 PRF

**Note:** These are empirical tests of necessary conditions. Formal security reductions are given in the accompanying research paper.

## Implementation Notes

**Go/C:**
- `crypto` package name is `falcon` (matches go-algorand for compatibility)
- CGO bindings to Falcon C reference implementation (NIST submission)
- Deterministic signature via `FALCON_DET512` fixed salt
- Keccak256 mode uses `/crypto/ntt_helper.c` for hash-to-point extraction

**Solidity:**
- `DFVRF_vrf_falcon.sol` -- SHAKE256 hash-to-point (NIST-compliant but gas-expensive)
- `DFVRF_vrf_falcon_evm.sol` -- Keccak256 hash-to-point (EVM-native, 63% cheaper gas)
- Both reuse `DFVRF_falcon_core.sol` for norm checking and s1 recovery
- `ntth` (NTT of public key) is passed by caller, not computed on-chain
- `ECDSAGasBaseline.sol`, `WitnetSecp256k1ECDSABaseline.sol`, and
  `WitnetVRFGasBaseline.sol` are test-only baseline contracts

**Build:**
- `hardhat.config.js` auto-excludes Foundry-only files (importing `forge-std`)
- Hardhat tests: `/test/VRFFalcon.test.js` (24 tests, 30s total)
- Foundry tests: `/contracts/test/*.t.sol` (compile separately with `forge test`)

**Fixtures:**
- `cmd/vrfjson` exports Go-generated proof + both SHAKE/Keccak modes to JSON
- Fixture includes: pk, proof, s2, ntth, transcript, salt, beta for both modes
- Used by Hardhat tests for E2E on-chain verification + gas measurement

## Known Limitations & Future Work

1. **Trust model for ntth:** Current design trusts the caller-provided ntth. Production use requires:
   - On-chain registry where identities register their ntth once
   - Or: Application trusts a specific beacon/oracle service
   - Optional on-chain NTT variants are implemented for trust-minimized registration
     and measured at +571,501 gas in the SHAKE verifier and +557,288 gas in the
     Keccak verifier

2. **Keccak mode domain separation:** Uses keccak(nonce || msg) internally; may conflict with other hash-to-point schemes. Standard practice is to vary the nonce structure.

3. **Performance:** 1.5M gas (Keccak) is still 50× more than ECVRF. Practical for:
   - Low-frequency operations (block proposals, entry points)
   - Applications willing to accept PQ security premium
   - **Not** suitable for per-transaction randomness

4. **Epervier support:** DFVRF_vrf_epervier.sol included but untested; needs integration tests

## References

- **FALCON:** NIST PQC Standardization, Aug 2024. https://csrc.nist.gov/Projects/post-quantum-cryptography/
- **ETHFALCON:** ZKNoxHQ, Efficient lattice verification on EVM. https://github.com/ZKNoxHQ/ETHFALCON
- **FALCON_DET:** Deterministic Falcon signing (go-algorand reference)
- **Witnet VRF Solidity:** secp256k1 ECVRF verifier and gas baseline. https://github.com/witnet/vrf-solidity
- **Witnet elliptic-curve-solidity:** Solidity secp256k1 arithmetic library used for non-`ecrecover` ECDSA/ECVRF baselines. https://github.com/witnet/elliptic-curve-solidity
- **go-ethereum `ecrecover` precompile tests:** reference vectors showing the 3,000 gas native precompile cost. https://github.com/ethereum/go-ethereum/blob/master/core/vm/testdata/precompiles/ecRecover.json
- **go-ethereum precompile implementation:** native `ecrecover` contract implementation in `core/vm/contracts.go`. https://github.com/ethereum/go-ethereum/blob/master/core/vm/contracts.go
- **EIP-2:** Ethereum Homestead low-s transaction signature rule; useful context for ECDSA malleability. https://eips.ethereum.org/EIPS/eip-2
- **RFC 6979:** deterministic ECDSA nonce generation. https://www.rfc-editor.org/rfc/rfc6979
- **RFC 9381:** Verifiable Random Functions. https://www.rfc-editor.org/rfc/rfc9381
- **Keccak256:** SHA-3 family hash exposed in the EVM as the `KECCAK256` opcode.
