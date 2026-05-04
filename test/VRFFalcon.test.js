/**
 * VRFFalcon.test.js
 *
 * Integration tests for ZKNOX_vrf_falcon and ZKNOX_vrf_epervier.
 *
 * ── Architecture note ────────────────────────────────────────────────────────
 * The Go layer uses Falcon-1024 (n=1024, 1024 polynomial coefficients).
 * The Solidity ZKNOX library was designed for Falcon-512 (n=512, 32 uint256
 * words per polynomial, 16 coefficients per word).
 *
 * On-chain Falcon-1024 verification requires:
 *   • ZKNOX_falcon_utils1024.sol  (n=1024, falcon_S1024=64, sigBound for 1024)
 *   • ZKNOX_NTT_falcon1024.sol    (2048-point NTT roots mod q=12289)
 *   • ZKNOX_vrf_falcon1024.sol    (updated length checks)
 *
 * Until those are implemented:
 *   • "Go bridge" tests validate the JSON fixture format.
 *   • "Falcon-512 smoke" tests verify the existing contracts behave correctly
 *     with correctly-shaped (but dummy) data.
 *   • The expected revert test documents the 512-vs-1024 gap explicitly.
 * ─────────────────────────────────────────────────────────────────────────────
 */

const { expect } = require("chai");
const { ethers } = require("hardhat");
const path = require("path");
const fs = require("fs");
const { execSync } = require("child_process");

// ── Helpers ──────────────────────────────────────────────────────────────────

/**
 * Pack an array of numeric coefficients (each 16-bit) into BigInt uint256 words.
 * 16 coefficients per word, little-endian within the word.
 * Negative values are reduced mod q=12289 before packing.
 */
function packCoeffs(coeffs, q = 12289n) {
  const numWords = Math.ceil(coeffs.length / 16);
  const words = [];
  for (let i = 0; i < numWords; i++) {
    let w = 0n;
    for (let j = 0; j < 16; j++) {
      const idx = i * 16 + j;
      if (idx >= coeffs.length) break;
      let v = BigInt(coeffs[idx]);
      if (v < 0n) v = q + v;
      w |= v << BigInt(j * 16);
    }
    words.push(w);
  }
  return words;
}

// 40-byte fixed salt for Falcon det1024, salt_version=0:
//   [0x00, 0x0A, 'F','A','L','C','O','N','_','D','E','T', 0x00×28]
const FIXED_SALT_1024 = new Uint8Array(40);
FIXED_SALT_1024[0] = 0x00; // salt_version
FIXED_SALT_1024[1] = 0x0a; // FALCON_DET1024_LOGN = 10
"FALCON_DET"
  .split("")
  .forEach((c, i) => (FIXED_SALT_1024[2 + i] = c.charCodeAt(0)));

// ── Fixtures ─────────────────────────────────────────────────────────────────

const FIXTURE_PATH = path.join(__dirname, "fixtures", "vrf_sample.json");

function loadOrBuildFixture() {
  if (!fs.existsSync(FIXTURE_PATH)) {
    try {
      execSync(`go run ./cmd/vrfjson -out ${FIXTURE_PATH}`, {
        cwd: path.join(__dirname, ".."),
        stdio: "pipe",
        timeout: 120_000,
      });
    } catch {
      return null;
    }
  }
  return JSON.parse(fs.readFileSync(FIXTURE_PATH, "utf8"));
}

// ── Test suites ───────────────────────────────────────────────────────────────

describe("ZKNOX_vrf_falcon", function () {
  let vrfFalcon;

  before(async function () {
    const Factory = await ethers.getContractFactory("ZKNOX_vrf_falcon");
    vrfFalcon = await Factory.deploy();
    await vrfFalcon.waitForDeployment();
  });

  it("deploys to a valid address", async function () {
    const addr = await vrfFalcon.getAddress();
    expect(ethers.isAddress(addr)).to.be.true;
  });

  describe("Falcon-512 smoke (correct-length dummy data)", function () {
    // 32 zero words = valid shape for Falcon-512, returns false (invalid sig)
    const dummyTranscript = new Uint8Array(64);
    const dummySalt = new Uint8Array(40);
    dummySalt[1] = 0x09; // logn=9 for n=512
    const dummyS2 = Array(32).fill(0n);
    const dummyNtth = Array(32).fill(0n);

    it("returns false for zero dummy data (invalid proof)", async function () {
      const result = await vrfFalcon.verify(
        dummyTranscript,
        dummySalt,
        dummyS2,
        dummyNtth
      );
      expect(result).to.be.false;
    });

    it("reverts on wrong salt length (< 40 bytes)", async function () {
      try {
        await vrfFalcon.verify(dummyTranscript, new Uint8Array(1), dummyS2, dummyNtth);
        expect.fail("expected revert");
      } catch (e) {
        expect(e.message).to.include("invalid salt length");
      }
    });

    it("reverts on wrong s2 length (64 words instead of 32)", async function () {
      // This is the error you get when passing Falcon-1024 data to the 512 contract.
      try {
        await vrfFalcon.verify(dummyTranscript, dummySalt, Array(64).fill(0n), dummyNtth);
        expect.fail("expected revert");
      } catch (e) {
        expect(e.message).to.include("invalid s2 length");
      }
    });
  });

  describe("Go VRF bridge (Falcon-1024)", function () {
    let fixture;

    before(function () {
      fixture = loadOrBuildFixture();
      if (!fixture) this.skip();
    });

    it("fixture contains expected fields", function () {
      const required = [
        "seed",
        "msg_hex",
        "transcript_hex",
        "fixed_salt_hex",
        "pk_hex",
        "proof_hex",
        "beta_hex",
        "s2_words",
        "h_words",
        "ntt_h_words",
      ];
      required.forEach((k) => expect(fixture).to.have.property(k));
    });

    it("s2_words is 32 elements (Falcon-512 packing: 512 coeffs / 16 per word)", function () {
      expect(fixture.s2_words).to.have.lengthOf(32);
    });

    it("h_words is 32 elements (public key polynomial, same shape)", function () {
      expect(fixture.h_words).to.have.lengthOf(32);
    });

    it("ntt_h_words is 32 elements (NTT(h) for Solidity verifier)", function () {
      expect(fixture.ntt_h_words).to.have.lengthOf(32);
    });

    it("fixed_salt_hex encodes exactly 40 bytes", function () {
      expect(fixture.fixed_salt_hex.replace(/^0x/, "")).to.have.lengthOf(80);
    });

    it("beta_hex encodes 64 bytes (SHA-512 output)", function () {
      expect(fixture.beta_hex.replace(/^0x/, "")).to.have.lengthOf(128);
    });

    it("verify() returns true with real Go-generated Falcon-512 proof and NTT(h)", async function () {
      const transcript = Buffer.from(fixture.transcript_hex, "hex");
      const salt = Buffer.from(fixture.fixed_salt_hex, "hex");
      const s2 = fixture.s2_words.map((w) => BigInt(w));
      const ntth = fixture.ntt_h_words.map((w) => BigInt(w));

      const result = await vrfFalcon.verify(transcript, salt, s2, ntth);
      expect(result).to.be.true;
    });
  });
});

describe("Gas benchmarks", function () {
  let vrfFalcon;
  let fixture;

  before(async function () {
    const Factory = await ethers.getContractFactory("ZKNOX_vrf_falcon");
    vrfFalcon = await Factory.deploy();
    await vrfFalcon.waitForDeployment();
    fixture = loadOrBuildFixture();
    if (!fixture) this.skip();
  });

  it("deployment gas", async function () {
    const tx = vrfFalcon.deploymentTransaction();
    const receipt = await tx.wait();
    console.log(`\n  [gas] ZKNOX_vrf_falcon deploy : ${receipt.gasUsed.toLocaleString()} gas`);
  });

  it("verify() gas — valid proof (returns true)", async function () {
    const transcript = Buffer.from(fixture.transcript_hex, "hex");
    const salt = Buffer.from(fixture.fixed_salt_hex, "hex");
    const s2 = fixture.s2_words.map((w) => BigInt(w));
    const ntth = fixture.ntt_h_words.map((w) => BigInt(w));

    const gas = await vrfFalcon.verify.estimateGas(transcript, salt, s2, ntth);
    console.log(`\n  [gas] verify() valid proof     : ${gas.toLocaleString()} gas`);
  });

  it("verify() gas — invalid proof (returns false, no revert)", async function () {
    const transcript = Buffer.from(fixture.transcript_hex, "hex");
    const salt = Buffer.from(fixture.fixed_salt_hex, "hex");
    const s2 = fixture.s2_words.map((w) => BigInt(w));
    const ntth = Array(32).fill(0n); // wrong ntth → returns false

    const gas = await vrfFalcon.verify.estimateGas(transcript, salt, s2, ntth);
    console.log(`\n  [gas] verify() invalid proof   : ${gas.toLocaleString()} gas`);
  });
});

describe("ZKNOX_vrf_epervier", function () {
  let vrfEpervier;

  before(async function () {
    const Factory = await ethers.getContractFactory("ZKNOX_vrf_epervier");
    vrfEpervier = await Factory.deploy();
    await vrfEpervier.waitForDeployment();
  });

  it("deploys to a valid address", async function () {
    const addr = await vrfEpervier.getAddress();
    expect(ethers.isAddress(addr)).to.be.true;
  });

  it("HashToAddress returns a valid Ethereum address for arbitrary input", async function () {
    const input = ethers.toUtf8Bytes("test");
    const addr = await vrfEpervier.HashToAddress(input);
    expect(ethers.isAddress(addr)).to.be.true;
  });

  it("recover reverts on wrong salt length", async function () {
    const dummyTranscript = new Uint8Array(64);
    const badSalt = new Uint8Array(1); // must be 40
    const cs1 = Array(32).fill(0n);
    const cs2 = Array(32).fill(0n);
    const hint = 0n;

    try {
      await vrfEpervier.recover(dummyTranscript, badSalt, cs1, cs2, hint);
      expect.fail("expected revert");
    } catch (e) {
      expect(e.message).to.include("wrong salt length");
    }
  });
});
