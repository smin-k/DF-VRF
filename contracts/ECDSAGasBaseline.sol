// SPDX-License-Identifier: MIT
pragma solidity ^0.8.25;

contract ECDSAGasBaseline {
    function recover(bytes32 digest, uint8 v, bytes32 r, bytes32 s) external pure returns (address) {
        return ecrecover(digest, v, r, s);
    }

    function verify(bytes32 digest, uint8 v, bytes32 r, bytes32 s, address expected) external pure returns (bool) {
        return ecrecover(digest, v, r, s) == expected;
    }
}
