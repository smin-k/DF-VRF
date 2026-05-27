// SPDX-License-Identifier: MIT
pragma solidity >=0.5.3 <0.7.0;

import "elliptic-curve-solidity/contracts/EllipticCurve.sol";

/// @notice Test-only ECDSA verifier over secp256k1 without ecrecover.
/// @dev Uses Witnet's Solidity elliptic-curve arithmetic library to measure
/// the gas scale of performing classical ECDSA verification in EVM code.
contract WitnetSecp256k1ECDSABaseline {
    uint256 private constant AA = 0;
    uint256 private constant BB = 7;
    uint256 private constant PP =
        0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F;
    uint256 private constant NN =
        0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141;
    uint256 private constant GX =
        0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798;
    uint256 private constant GY =
        0x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8;

    function verify(
        bytes32 digest,
        uint256 r,
        uint256 s,
        uint256 qx,
        uint256 qy
    ) external pure returns (bool) {
        if (r == 0 || r >= NN || s == 0 || s >= NN) return false;
        if (!EllipticCurve.isOnCurve(qx, qy, AA, BB, PP)) return false;

        uint256 w = EllipticCurve.invMod(s, NN);
        uint256 u1 = mulmod(uint256(digest), w, NN);
        uint256 u2 = mulmod(r, w, NN);

        (uint256 x1, uint256 y1) = EllipticCurve.ecMul(u1, GX, GY, AA, PP);
        (uint256 x2, uint256 y2) = EllipticCurve.ecMul(u2, qx, qy, AA, PP);
        (uint256 x,) = EllipticCurve.ecAdd(x1, y1, x2, y2, AA, PP);

        return x % NN == r;
    }
}
