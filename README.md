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

## Notes

- The `crypto` directory package name is `falcon` for API compatibility.
- Solidity sources are kept under `contracts/` to separate on-chain code from Go/C code.
