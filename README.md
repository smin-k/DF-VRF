# DF-VRF

Deterministic Falcon-512-based VRF experimental repository.

## Directory Layout

- `crypto/`: C implementation + Go bindings for deterministic Falcon-512 and VRF APIs.
- `contracts/`: Solidity contracts and Foundry test files.
- `contracts/test/`: Foundry-only test suite (`.t.sol`). Not compiled by Hardhat.
- `cmd/`: CLI entry points.
  - `cmd/vrfexp`: VRF sample generator (CSV output).
  - `cmd/vrfjson`: VRF fixture exporter (JSON, for Hardhat integration tests).
- `scripts/`: Hardhat deployment scripts.
- `test/`: Hardhat/Mocha integration tests.

## Go Module

- Module path: `DF_VRF`
- Crypto engine import path: `DF_VRF/crypto`

## Quick Start (Go)

Build CLIs:

```bash
go build ./cmd/vrfexp
go build ./cmd/vrfjson
```

Run core tests:

```bash
go test ./crypto/...
```

Run selected Keccak mode tests:

```bash
go test ./crypto -run 'TestFalconKeccakMode|TestFalconVRFKeccakMode'
```

## Quick Start (Hardhat)

Install dependencies and compile contracts:

```bash
npm install
npm run compile
```

Run Hardhat integration tests (also exercises the Go VRF bridge):

```bash
npm test
```

Generate a VRF fixture JSON from Go:

```bash
npm run vrf:export
# → test/fixtures/vrf_sample.json
```

Deploy to local Hardhat node:

```bash
npx hardhat node          # terminal 1
npm run deploy:local      # terminal 2
```

## On-chain verification architecture

| Layer | Status |
|-------|--------|
| Go VRF prove/verify (Falcon-512, n=512) | ✅ complete |
| Hardhat compilation + deployment scripts | ✅ complete |
| `ZKNOX_vrf_falcon` Solidity verifier (Falcon-512, n=512) | ✅ compiles, deploys, and matches Go output |
| `ZKNOX_vrf_epervier` Solidity verifier | ✅ compiles and deploys |

Go and Solidity both use Falcon-512 (polynomial degree n=512, 32 uint256 words per
polynomial). The Go layer generates proofs; the Solidity verifier checks the shape and
signature components produced by the Go layer.

## Cryptographic parameters

| Parameter | Value |
|-----------|-------|
| Algorithm | Falcon-512 (deterministic mode) |
| Degree | n = 512 |
| Modulus | q = 12289 |
| logn | 9 |
| Fixed salt | 40 bytes: `[0x00, 0x09, "FALCON_DET", 0x00×28]` |
| VRF transcript | SHA-512(`"FALCON-VRF-PROVE-v1"` ‖ pk ‖ msg) |
| VRF output β | SHA-512(`"FALCON-VRF-BETA-v1"` ‖ pk ‖ msg ‖ proof) |
| Polynomial packing | 16 coefficients per uint256 word (16-bit slots) |
| s2 / h word count | 32 words (512 coefficients / 16 per word) |

## Notes

- The `crypto` directory package name is `falcon` for API compatibility.
- Solidity sources are kept under `contracts/` to separate on-chain code from Go/C code.
- Hardhat excludes Foundry-only files (those importing `forge-std`, `sstore2`,
  `InterfaceVerifier`) automatically via `hardhat.config.js`.
- Foundry tests live in `contracts/test/` and are compiled separately with `forge test`.
