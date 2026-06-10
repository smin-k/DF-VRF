// Copyright (C) 2026 - ZKNOX
// License: This software is licensed under MIT License
// This Code may be reused including this header, license and copyright notice.
// FILE: DFVRF_vrf_falcon_evm.sol
// Description: EVM-optimized VRF verifier for Falcon proofs
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.25;

import "./DFVRF_common.sol";
import "./DFVRF_falcon_utils.sol";
import "./DFVRF_falcon_core.sol";
import "./DFVRF_HashToPoint.sol";

/// @title ZKNOX_vrf_falcon_evm
/// @notice EVM-optimised Falcon-512 VRF verifier using Keccak256 hash-to-point
/// @dev Identical to ZKNOX_vrf_falcon except hashToPointEVM (Keccak256) replaces
///      hashToPointNIST (SHAKE256). Keccak256 is a native EVM precompile so gas
///      cost is substantially lower; the trade-off is loss of NIST/FIPS compliance.
contract ZKNOX_vrf_falcon_evm {
    function verify(
        bytes memory transcript,
        bytes memory salt,
        uint256[] memory s2,
        uint256[] memory ntth
    ) external pure returns (bool result) {
        if (salt.length != SALT_LEN) {
            revert("invalid salt length");
        }
        if (s2.length != falcon_S256) {
            revert("invalid s2 length");
        }
        if (ntth.length != falcon_S256) {
            revert("invalid ntth length");
        }

        uint256[] memory hashed = hashToPointEVM(salt, transcript);
        result = falcon_core(s2, ntth, hashed);
    }
}
