const { ethers, network } = require("hardhat");

async function main() {
  const [deployer] = await ethers.getSigners();
  const chain = await ethers.provider.getNetwork();
  const balance = await ethers.provider.getBalance(deployer.address);

  console.log(`[witnet-ecdsa] network       : ${network.name} (chainId=${chain.chainId})`);
  console.log(`[witnet-ecdsa] deployer      : ${deployer.address}`);
  console.log(`[witnet-ecdsa] balance       : ${ethers.formatEther(balance)} ETH`);

  const Factory = await ethers.getContractFactory("WitnetSecp256k1ECDSABaseline");
  const contract = await Factory.deploy();
  const deployReceipt = await contract.deploymentTransaction().wait();
  const address = await contract.getAddress();

  const wallet = new ethers.Wallet(
    "0x59c6995e998f97a5a0044966f094538e7ddc9e0a9e2b68e0c5f0a8a8b5f9b1d7"
  );
  const digest = ethers.keccak256(ethers.toUtf8Bytes("df-vrf-pure-ecdsa-baseline"));
  const sig = wallet.signingKey.sign(digest);
  const publicKey = wallet.signingKey.publicKey;
  const qx = `0x${publicKey.slice(4, 68)}`;
  const qy = `0x${publicKey.slice(68, 132)}`;

  const valid = await contract.verify.staticCall(digest, sig.r, sig.s, qx, qy);
  const verifyGas = await contract.verify.estimateGas(digest, sig.r, sig.s, qx, qy);

  const data = contract.interface.encodeFunctionData("verify", [digest, sig.r, sig.s, qx, qy]);
  const tx = await deployer.sendTransaction({ to: address, data, gasLimit: verifyGas + 1_000_000n });
  const receipt = await tx.wait();

  console.log(`[witnet-ecdsa] contract      : ${address}`);
  console.log(`[witnet-ecdsa] deploy gas    : ${deployReceipt.gasUsed.toLocaleString()}`);
  console.log(`[witnet-ecdsa] public key    : ${publicKey}`);
  console.log(`[witnet-ecdsa] valid         : ${valid}`);
  console.log(`[witnet-ecdsa] verify est    : ${verifyGas.toLocaleString()} gas`);
  console.log(`[witnet-ecdsa] verify tx gas : ${receipt.gasUsed.toLocaleString()} gas`);
}

main().catch((error) => {
  console.error(error);
  process.exitCode = 1;
});
