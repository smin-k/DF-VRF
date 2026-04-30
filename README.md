# DF-VRF

Deterministic Falcon-based VRF experimental repository.

## Directory Layout

- `crypto/`: C implementation + Go bindings for deterministic Falcon and VRF APIs.
- `contracts/`: Solidity contracts and Solidity tests.
- `cmd/`: CLI entrypoints.
  - `cmd/vrfexp`: VRF sample generator.

## Go Module

- Module path: `DF_VRF`
- Main package import path for crypto engine: `DF_VRF/crypto`

## Quick Start (Go)

Build CLI:

```bash
go build ./cmd/vrfexp
```

Run core tests:

```bash
go test ./crypto
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

Run Hardhat tests (also exercises the Go VRF bridge):

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

### On-chain verification architecture

| Layer | Status |
|-------|--------|
| Go VRF prove/verify (Falcon-1024, n=1024) | ✅ complete |
| Hardhat compilation + deployment scripts | ✅ complete |
| `ZKNOX_vrf_falcon` Solidity verifier (Falcon-512, n=512) | ✅ compiles & deploys |
| **Falcon-1024 Solidity verifier** (`ZKNOX_vrf_falcon1024.sol`) | ⬜ TODO |

The existing ZKNOX Solidity library targets Falcon-512 (polynomial degree n=512,
32 uint256 words per polynomial).  The Go layer uses Falcon-1024 (n=1024, 64 words).
Full end-to-end on-chain verification of Go-generated proofs requires:
- `contracts/ZKNOX_falcon_utils1024.sol` — constants for n=1024
- `contracts/ZKNOX_NTT_falcon1024.sol` — 2048-point NTT roots mod q=12289
- `contracts/ZKNOX_vrf_falcon1024.sol` — updated length checks

Until then, `test/VRFFalcon.test.js` documents the gap with an explicit revert
test and validates the entire data pipeline from Go to Solidity call.

## Notes

- The `crypto` directory package name is `falcon` for API compatibility.
- Solidity sources are kept under `contracts/` to separate on-chain code from Go/C code.
- Hardhat excludes Foundry-only files (those importing `forge-std`, `sstore2`,
  `InterfaceVerifier`) automatically via `hardhat.config.js`.
