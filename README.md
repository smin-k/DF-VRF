# DF-VRF: Post-Quantum VRF for Ethereum

Deterministic Falcon-512–based Verifiable Random Function (VRF) with practical on-chain verification on EVM.

**Key contribution:** First practical Falcon-based VRF with on-chain Solidity verifier, combining FALCON_DET determinism, ETHFALCON's NTT-domain verification, and Keccak256-based hash-to-point for EVM efficiency.

## Features

- **Deterministic signing:** FALCON_DET512 eliminates randomness; same (sk, msg) → same proof.
- **Two hash-to-point modes:**
  - **SHAKE256** (NIST-compliant): 4,051,960 gas on Ethereum
  - **Keccak256** (EVM-optimized): 1,487,710 gas on Ethereum — 63% cheaper via native precompile
- **Compact proofs:** Average 618 B (SHAKE) or 657 B (Keccak), vs 5 KB for LB-VRF or 12 KB for LaV
- **Fast off-chain:** Prove 3.35 ms, Verify 0.023 ms (SHAKE256)
- **Security properties tested:** Determinism, injectivity, pseudorandomness stats, no collisions

## Directory Layout

- `crypto/`: C implementation (Falcon-512 det, Keccak support) + Go bindings for VRF API
  - `falcon.go` — public/private key types, signing, VRF Prove/Verify
  - `df_vrf.go` — VRF transcript and output derivation
  - `ntt_helper.c` — NTT computation and Keccak proof extraction
  - `*_test.go` — unit tests + security property tests
- `contracts/`: Solidity verification contracts
  - `ZKNOX_vrf_falcon.sol` — SHAKE256 mode verifier
  - `ZKNOX_vrf_falcon_evm.sol` — Keccak256 mode verifier (gas-optimized)
  - `ZKNOX_vrf_epervier.sol` — Epervier-based variants
- `cmd/vrfjson/` — Go CLI exporting test fixtures (for Hardhat)
- `test/` — Hardhat/Mocha E2E tests with gas benchmarks

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

| Verifier | Gas Cost | vs ECVRF |
|----------|----------|----------|
| `verify()` SHAKE256 | 4,051,960 | 135x |
| `verify()` Keccak256 | **1,487,710** | 50x |
| Deploy | ~1M | baseline |

**Note:** ECVRF ≈ 30K gas (secp256k1, not PQ-secure). Keccak mode gains 63% efficiency by replacing SHAKE256 with EVM's native Keccak256 precompile.

## Comparison with Other Post-Quantum VRFs

| Scheme | Security | PK (B) | Proof (B) | Prove (ms) | Verify (ms) | On-chain |
|--------|----------|--------|-----------|------------|------------|----------|
| LB-VRF | Mod-SIS/LWE | 3,320 | ~5,000 | ~3 | ~1 | ✗ |
| LaV | Mod-LWE | 6,420 | ~12,000 | — | — | ✗ |
| X-VRF | Hash (XMSS) | ~2,000 | ≤3,000 | — | — | ✗† |
| DeuringVRF | Isogeny | 224 | 226 | ~160 | ~18 | ✗ |
| **DF-VRF** | **NTRU** | **897** | **618** | **3.35** | **0.023** | ✅ |

†X-VRF's uniqueness was broken in 2024.

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

Generate test fixture from Go:

```bash
npm run vrf:export
# → test/fixtures/vrf_sample.json
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

1. **Off-chain (Go):** Generate VRF proof π = signature(transcript)
2. **Off-chain:** Compute ntth = NTT(h) once per public key
3. **On-chain call:** `verify(transcript, salt, s2, ntth)`
4. **On-chain (Solidity):** 
   - Recover c = Falcon challenge from transcript
   - Compute s1 = INTT(NTT(s2) ⊙ ntth)
   - Check ||c - s1||² + ||s2||² < sigBound

**Cost reduction:** Eliminates on-chain NTT (most expensive operation), reducing gas from 4M→1.5M.

**Trust model:** The ntth witness is trusted to be correct. In production, either:
- Verifier has registered ntth in an on-chain registry by its own computation
- Or: Application trusts a specific off-chain server (similar to beacon services)

### Implementation Status

| Component | Status |
|-----------|--------|
| Go VRF prove/verify (Falcon-512, deterministic) | ✅ complete |
| Keccak256 hash-to-point (Go) | ✅ complete |
| NTT computation (Go) | ✅ complete |
| ZKNOX_vrf_falcon (SHAKE256 verifier) | ✅ verified, 4M gas |
| ZKNOX_vrf_falcon_evm (Keccak256 verifier) | ✅ verified, 1.5M gas |
| ZKNOX_vrf_epervier (Epervier verifier) | ✅ compiles, untested |
| Security property tests | ✅ 9/9 passing |

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
| **VRF transcript** | SHA-512(`"FALCON-VRF-PROVE-v1"` ‖ pk ‖ msg) |
| **VRF output β** | SHA-512(`"FALCON-VRF-BETA-v1"` ‖ pk ‖ msg ‖ proof) |
| **Polynomial packing** | 16 coefficients × 16 bits per uint256 word |
| **s2 / h word count** | 32 words (512 coefficients ÷ 16 per word) |

## Security Properties

DF-VRF satisfies the three standard VRF properties:

### 1. Correctness (Provability)
- ✅ **Tested:** `TestFalconVRFRoundTrip` — Prove → Verify always succeeds
- **Basis:** Falcon-512 signature correctness

### 2. Uniqueness
- ✅ **Tested:** `TestVRFUniqueness_Determinism` — same (sk, msg) → same proof
- ✅ **Tested:** `TestVRFUniqueness_DifferentKeys` — different pk → different output
- ✅ **Tested:** `TestVRFUniqueness_DifferentMessages` — different msg → different output
- ✅ **Tested:** `TestVRFUniqueness_ProofBinding` — tampered proof ≠ same output
- **Basis:** FALCON_DET determinism + Falcon unforgeability

### 3. Pseudorandomness (statistical)
- ✅ **Tested:** `TestVRFPseudorandomness_ByteDistribution` — chi² = 247 (critical = 332)
- ✅ **Tested:** `TestVRFPseudorandomness_AvalancheEffect` — 1-bit input change flips ~57% of output
- ✅ **Tested:** `TestVRFPseudorandomness_NoCollisions` — 1,000 samples, 0 collisions
- ✅ **Tested:** `TestVRFPseudorandomness_BitBalance` — bit balance mean = 0.501
- **Basis:** Falcon unforgeability + SHA-512 PRF

**Note:** These are empirical tests of necessary conditions. Formal security reductions are given in the accompanying research paper.

## Implementation Notes

**Go/C:**
- `crypto` package name is `falcon` (matches go-algorand for compatibility)
- CGO bindings to Falcon C reference implementation (NIST submission)
- Deterministic signature via `FALCON_DET512` fixed salt
- Keccak256 mode uses `/crypto/ntt_helper.c` for hash-to-point extraction

**Solidity:**
- `ZKNOX_vrf_falcon.sol` — SHAKE256 hash-to-point (NIST-compliant but gas-expensive)
- `ZKNOX_vrf_falcon_evm.sol` — Keccak256 hash-to-point (EVM-native, 63% cheaper gas)
- Both reuse `ZKNOX_falcon_core.sol` for norm checking and s1 recovery
- `ntth` (NTT of public key) is passed by caller, not computed on-chain

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
   - Future: Add on-chain NTT computation (feasible but ~2–3M additional gas)

2. **Keccak mode domain separation:** Uses keccak(nonce || msg) internally; may conflict with other hash-to-point schemes. Standard practice is to vary the nonce structure.

3. **Performance:** 1.5M gas (Keccak) is still 50× more than ECVRF. Practical for:
   - Low-frequency operations (block proposals, entry points)
   - Applications willing to accept PQ security premium
   - **Not** suitable for per-transaction randomness

4. **Epervier support:** ZKNOX_vrf_epervier.sol included but untested; needs integration tests

## References

- **FALCON:** NIST PQC Standardization, Aug 2024. https://csrc.nist.gov/Projects/post-quantum-cryptography/
- **ETHFALCON:** ZKNoxHQ, Efficient lattice verification on EVM. https://github.com/ZKNoxHQ/ETHFALCON
- **FALCON_DET:** Deterministic Falcon signing (go-algorand reference)
- **Keccak256:** SHA-3 family, used as EVM precompile (0x0001)
