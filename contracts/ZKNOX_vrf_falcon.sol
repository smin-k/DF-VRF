// Copyright (C) 2026 - ZKNOX
// License: This software is licensed under MIT License
// This Code may be reused including this header, license and copyright notice.
// FILE: ZKNOX_vrf_falcon.sol
// Description: VRF verifier for Falcon proofs
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.25;

import "./ZKNOX_common.sol";
import "./ZKNOX_falcon_utils.sol";
import "./ZKNOX_falcon_core.sol";
import "./ZKNOX_HashToPoint.sol";

/// @title ZKNOX_vrf_falcon
/// @notice Verifies Falcon VRF proofs against the VRF transcript
/// @dev The transcript is the off-chain 64-byte VRF transcript computed in Go
///      (domain || public key || message). The proof layout remains salt + s2.
contract ZKNOX_vrf_falcon {
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

        uint256[] memory hashed = hashToPointNIST(salt, transcript);
        result = falcon_core(s2, ntth, hashed);
    }
}