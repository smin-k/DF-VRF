// SPDX-License-Identifier: MIT
pragma solidity ^0.8.25;

/// @notice Test-only gas proxy for DeuringVRF-style finite-field arithmetic.
/// @dev This is not a DeuringVRF verifier. It measures the cost scale of
/// 249-bit custom-prime Fp/Fp2 arithmetic and elliptic-curve operations that
/// Ethereum does not provide as native precompiles.
contract DeuringArithmeticGasBaseline {
    // DeuringVRF example parameter from ePrint 2023/1251: p + 1 = 305 * 2^240.
    uint256 public constant P =
        0x130FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF;
    uint256 private constant A = 1;

    struct Fp2 {
        uint256 a;
        uint256 b;
    }

    function fpAdd(uint256 x, uint256 y) public pure returns (uint256) {
        return addmod(x, y, P);
    }

    function fpMul(uint256 x, uint256 y) public pure returns (uint256) {
        return mulmod(x, y, P);
    }

    function fpMulLoop(uint256 x, uint256 y, uint256 rounds) external pure returns (uint256 z) {
        z = x % P;
        for (uint256 i = 0; i < rounds; i++) {
            z = mulmod(z, y + i, P);
        }
    }

    function fpInv(uint256 x) public pure returns (uint256) {
        require(x != 0, "zero inverse");
        return _modExp(x, P - 2);
    }

    function fp2Mul(
        uint256 a0,
        uint256 a1,
        uint256 b0,
        uint256 b1
    ) public pure returns (uint256 c0, uint256 c1) {
        // Fp2 = Fp[i] / (i^2 + 1), valid for p = 3 mod 4.
        c0 = addmod(mulmod(a0, b0, P), P - mulmod(a1, b1, P), P);
        c1 = addmod(mulmod(a0, b1, P), mulmod(a1, b0, P), P);
    }

    function fp2MulLoop(
        uint256 a0,
        uint256 a1,
        uint256 b0,
        uint256 b1,
        uint256 rounds
    ) external pure returns (uint256 c0, uint256 c1) {
        c0 = a0 % P;
        c1 = a1 % P;
        for (uint256 i = 0; i < rounds; i++) {
            (c0, c1) = fp2Mul(c0, c1, addmod(b0, i, P), b1);
        }
    }

    function fp2Inv(
        uint256 a0,
        uint256 a1
    ) public pure returns (uint256 c0, uint256 c1) {
        uint256 norm = addmod(mulmod(a0, a0, P), mulmod(a1, a1, P), P);
        uint256 invNorm = fpInv(norm);
        c0 = mulmod(a0, invNorm, P);
        c1 = a1 == 0 ? 0 : P - mulmod(a1, invNorm, P);
    }

    function ecFp2Add(
        uint256[8] calldata input
    ) external pure returns (uint256 x3a, uint256 x3b, uint256 y3a, uint256 y3b) {
        uint256[8] memory p = input;
        return _ecFp2Add(p);
    }

    function ecFp2Double(
        uint256[4] calldata input
    ) external pure returns (uint256 x3a, uint256 x3b, uint256 y3a, uint256 y3b) {
        uint256[4] memory p = input;
        return _ecFp2Double(p);
    }

    function ecFp2DoubleLoop(
        uint256[4] calldata input,
        uint256 rounds
    ) external pure returns (uint256 qxa, uint256 qxb, uint256 qya, uint256 qyb) {
        uint256[4] memory p = input;
        for (uint256 i = 0; i < rounds; i++) {
            (p[0], p[1], p[2], p[3]) = _ecFp2Double(p);
        }
        return (p[0], p[1], p[2], p[3]);
    }

    function _ecFp2Add(
        uint256[8] memory p
    ) private pure returns (uint256 x3a, uint256 x3b, uint256 y3a, uint256 y3b) {
        uint256 l0;
        uint256 l1;
        {
            (uint256 dx0, uint256 dx1) = _fp2Sub(p[4], p[5], p[0], p[1]);
            (uint256 dy0, uint256 dy1) = _fp2Sub(p[6], p[7], p[2], p[3]);
            (uint256 inv0, uint256 inv1) = fp2Inv(dx0, dx1);
            (l0, l1) = fp2Mul(dy0, dy1, inv0, inv1);
        }
        {
            (uint256 l20, uint256 l21) = fp2Mul(l0, l1, l0, l1);
            (x3a, x3b) = _fp2Sub(l20, l21, addmod(p[0], p[4], P), addmod(p[1], p[5], P));
        }
        {
            (uint256 t0, uint256 t1) = _fp2Sub(p[0], p[1], x3a, x3b);
            (uint256 lt0, uint256 lt1) = fp2Mul(l0, l1, t0, t1);
            (y3a, y3b) = _fp2Sub(lt0, lt1, p[2], p[3]);
        }
    }

    function _ecFp2Double(
        uint256[4] memory p
    ) private pure returns (uint256 x3a, uint256 x3b, uint256 y3a, uint256 y3b) {
        uint256 l0;
        uint256 l1;
        {
            (uint256 x20, uint256 x21) = fp2Mul(p[0], p[1], p[0], p[1]);
            uint256 num0 = addmod(mulmod(3, x20, P), A, P);
            uint256 num1 = mulmod(3, x21, P);
            uint256 den0 = addmod(p[2], p[2], P);
            uint256 den1 = addmod(p[3], p[3], P);
            (uint256 inv0, uint256 inv1) = fp2Inv(den0, den1);
            (l0, l1) = fp2Mul(num0, num1, inv0, inv1);
        }
        {
            (uint256 l20, uint256 l21) = fp2Mul(l0, l1, l0, l1);
            (x3a, x3b) = _fp2Sub(l20, l21, addmod(p[0], p[0], P), addmod(p[1], p[1], P));
        }
        {
            (uint256 t0, uint256 t1) = _fp2Sub(p[0], p[1], x3a, x3b);
            (uint256 lt0, uint256 lt1) = fp2Mul(l0, l1, t0, t1);
            (y3a, y3b) = _fp2Sub(lt0, lt1, p[2], p[3]);
        }
    }

    function _fp2Sub(
        uint256 a0,
        uint256 a1,
        uint256 b0,
        uint256 b1
    ) private pure returns (uint256 c0, uint256 c1) {
        c0 = addmod(a0, P - b0, P);
        c1 = addmod(a1, P - b1, P);
    }

    function _modExp(uint256 base, uint256 exponent) private pure returns (uint256 result) {
        result = 1;
        uint256 x = base % P;
        while (exponent != 0) {
            if (exponent & 1 == 1) {
                result = mulmod(result, x, P);
            }
            exponent >>= 1;
            if (exponent != 0) {
                x = mulmod(x, x, P);
            }
        }
    }
}
