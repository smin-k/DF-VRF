// Copyright (C) 2026 - ZKNOX
// License: This software is licensed under MIT License
// This Code may be reused including this header, license and copyright notice.
// FILE: DFVRF_vrf_falcon_evm_onchain_ntt.sol
// Description: Benchmark-only VRF verifier that computes NTT(h) on-chain
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.25;

import "./DFVRF_common.sol";
import "./DFVRF_falcon_utils.sol";
import "./DFVRF_falcon_core.sol";
import "./DFVRF_HashToPoint.sol";

/// @title ZKNOX_vrf_falcon_evm_onchain_ntt
/// @notice Benchmark helper for measuring the gas saved by passing ntth as a witness.
/// @dev This contract keeps Keccak hash-to-point fixed, but computes NTT(h)
///      on-chain from the compact public key. Production verifier uses
///      ZKNOX_vrf_falcon_evm and receives ntth directly.
contract ZKNOX_vrf_falcon_evm_onchain_ntt {
    function verify(
        bytes memory transcript,
        bytes memory salt,
        uint256[] memory s2,
        uint256[] memory h
    ) external pure returns (bool result) {
        if (salt.length != SALT_LEN) {
            revert("invalid salt length");
        }
        if (s2.length != falcon_S256) {
            revert("invalid s2 length");
        }
        if (h.length != falcon_S256) {
            revert("invalid h length");
        }

        uint256[] memory hashed = hashToPointEVM(salt, transcript);
        uint256[] memory ntth = _ZKNOX_NTT_Compact(_ZKNOX_NTTFW_vectorized(_ZKNOX_NTT_Expand(h)));
        result = falcon_core(s2, ntth, hashed);
    }
}
