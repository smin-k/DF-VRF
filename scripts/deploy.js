const hre = require("hardhat");

async function main() {
  const [deployer] = await hre.ethers.getSigners();
  console.log("Deployer:", deployer.address);
  console.log(
    "Balance:  ",
    hre.ethers.formatEther(await hre.ethers.provider.getBalance(deployer.address)),
    "ETH"
  );

  // ── ZKNOX_vrf_falcon ─────────────────────────────────────────────────────
  // Pure verifier: accepts (transcript, salt, s2, ntth) and returns bool.
  // Current implementation is for Falcon-512 (32-word s2 / ntth).
  const VRFFalcon = await hre.ethers.getContractFactory("ZKNOX_vrf_falcon");
  const vrfFalcon = await VRFFalcon.deploy();
  await vrfFalcon.waitForDeployment();
  const vrfFalconAddr = await vrfFalcon.getAddress();
  console.log("ZKNOX_vrf_falcon  →", vrfFalconAddr);

  // ── ZKNOX_vrf_epervier ───────────────────────────────────────────────────
  // Recover variant: returns Ethereum address derived from the VRF proof.
  const VRFEpervier = await hre.ethers.getContractFactory("ZKNOX_vrf_epervier");
  const vrfEpervier = await VRFEpervier.deploy();
  await vrfEpervier.waitForDeployment();
  const vrfEpervierAddr = await vrfEpervier.getAddress();
  console.log("ZKNOX_vrf_epervier→", vrfEpervierAddr);

  // Write addresses to a local file so tests can import them without re-deploying.
  const fs = require("fs");
  const addrs = { vrfFalcon: vrfFalconAddr, vrfEpervier: vrfEpervierAddr };
  fs.writeFileSync(
    "deployments.json",
    JSON.stringify(addrs, null, 2),
    "utf8"
  );
  console.log("Addresses written to deployments.json");
}

main().catch((err) => {
  console.error(err);
  process.exitCode = 1;
});
