// SPDX-License-Identifier: MIT
pragma solidity 0.6.12;
pragma experimental ABIEncoderV2;

import "vrf-solidity/contracts/VRF.sol";

/// @notice Test-only wrapper exposing Witnet's secp256k1 ECVRF library.
contract WitnetVRFGasBaseline {
    function decodeProof(bytes memory proof) public pure returns (uint256[4] memory) {
        return VRF.decodeProof(proof);
    }

    function decodePoint(bytes memory point) public pure returns (uint256[2] memory) {
        return VRF.decodePoint(point);
    }

    function computeFastVerifyParams(
        uint256[2] memory publicKey,
        uint256[4] memory proof,
        bytes memory message
    )
        public
        pure
        returns (uint256[2] memory, uint256[4] memory)
    {
        return VRF.computeFastVerifyParams(publicKey, proof, message);
    }

    function verify(
        uint256[2] memory publicKey,
        uint256[4] memory proof,
        bytes memory message
    )
        public
        pure
        returns (bool)
    {
        return VRF.verify(publicKey, proof, message);
    }

    function fastVerify(
        uint256[2] memory publicKey,
        uint256[4] memory proof,
        bytes memory message,
        uint256[2] memory uPoint,
        uint256[4] memory vComponents
    )
        public
        pure
        returns (bool)
    {
        return VRF.fastVerify(publicKey, proof, message, uPoint, vComponents);
    }

    function gammaToHash(uint256 gammaX, uint256 gammaY) public pure returns (bytes32) {
        return VRF.gammaToHash(gammaX, gammaY);
    }

    function hashToTryAndIncrement(
        uint256[2] memory publicKey,
        bytes memory message
    )
        public
        pure
        returns (uint256, uint256)
    {
        return VRF.hashToTryAndIncrement(publicKey, message);
    }

    function hashPoints(
        uint256 hPointX,
        uint256 hPointY,
        uint256 gammaX,
        uint256 gammaY,
        uint256 uPointX,
        uint256 uPointY,
        uint256 vPointX,
        uint256 vPointY
    )
        public
        pure
        returns (bytes16)
    {
        return VRF.hashPoints(hPointX, hPointY, gammaX, gammaY, uPointX, uPointY, vPointX, vPointY);
    }

    function ecMulSubMul(
        uint256 scalar1,
        uint256 a1,
        uint256 a2,
        uint256 scalar2,
        uint256 b1,
        uint256 b2
    )
        public
        pure
        returns (uint256, uint256)
    {
        return VRF.ecMulSubMul(scalar1, a1, a2, scalar2, b1, b2);
    }
}
