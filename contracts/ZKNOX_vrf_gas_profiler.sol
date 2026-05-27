// Copyright (C) 2026 - ZKNOX
// License: This software is licensed under MIT License
// This Code may be reused including this header, license and copyright notice.
// FILE: ZKNOX_vrf_gas_profiler.sol
// Description: Test-only gas profiler for DF-VRF verifier stages
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.25;

import "./ZKNOX_HashToPoint.sol";
import "./ZKNOX_NTT_falcon.sol";
import "./ZKNOX_falcon_core.sol";

contract ZKNOX_vrf_gas_profiler {
    function hashToPointShake(bytes memory salt, bytes memory transcript) external pure returns (uint256[] memory) {
        return hashToPointNIST(salt, transcript);
    }

    function hashToPointKeccak(bytes memory salt, bytes memory transcript) external pure returns (uint256[] memory) {
        return hashToPointEVM(salt, transcript);
    }

    function expandS2(uint256[] memory s2) external pure returns (uint256[] memory) {
        return _ZKNOX_NTT_Expand(s2);
    }

    function nttS2(uint256[] memory s2) external pure returns (uint256[] memory) {
        return _ZKNOX_NTTFW_vectorized(_ZKNOX_NTT_Expand(s2));
    }

    function expandNtth(uint256[] memory ntth) external pure returns (uint256[] memory) {
        return _ZKNOX_NTT_Expand(ntth);
    }

    function pointwiseMul(uint256[] memory ntts2, uint256[] memory expandedNtth)
        external
        pure
        returns (uint256[] memory)
    {
        return _ZKNOX_VECMULMOD(ntts2, expandedNtth);
    }

    function intt(uint256[] memory product) external pure returns (uint256[] memory) {
        return _ZKNOX_NTTINV_vectorized(product);
    }

    function compact(uint256[] memory expanded) external pure returns (uint256[] memory) {
        return _ZKNOX_NTT_Compact(expanded);
    }

    function halfmulCompact(uint256[] memory s2, uint256[] memory ntth) external pure returns (uint256[] memory) {
        return _ZKNOX_NTT_HALFMUL_Compact(s2, ntth);
    }

    function normalize(uint256[] memory s1, uint256[] memory s2, uint256[] memory hashed)
        external
        pure
        returns (bool)
    {
        return falcon_normalize(s1, s2, hashed);
    }

    function core(uint256[] memory s2, uint256[] memory ntth, uint256[] memory hashed) external pure returns (bool) {
        return falcon_core(s2, ntth, hashed);
    }
}
