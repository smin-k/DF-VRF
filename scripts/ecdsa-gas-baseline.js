const { ethers, network } = require("hardhat");

async function main() {
  const [deployer] = await ethers.getSigners();
  const chain = await ethers.provider.getNetwork();
  const balance = await ethers.provider.getBalance(deployer.address);

  console.log(`[ecdsa] network       : ${network.name} (chainId=${chain.chainId})`);
  console.log(`[ecdsa] deployer      : ${deployer.address}`);
  console.log(`[ecdsa] balance       : ${ethers.formatEther(balance)} ETH`);

  const Factory = await ethers.getContractFactory("ECDSAGasBaseline");
  const contract = await Factory.deploy();
  const deployReceipt = await contract.deploymentTransaction().wait();
  const address = await contract.getAddress();

  const message = "df-vrf-ecdsa-baseline";
  const digest = ethers.hashMessage(message);
  const sig = ethers.Signature.from(await deployer.signMessage(message));

  const recovered = await contract.recover.staticCall(digest, sig.v, sig.r, sig.s);
  const valid = await contract.verify.staticCall(digest, sig.v, sig.r, sig.s, deployer.address);
  const recoverGas = await contract.recover.estimateGas(digest, sig.v, sig.r, sig.s);
  const verifyGas = await contract.verify.estimateGas(digest, sig.v, sig.r, sig.s, deployer.address);

  const data = contract.interface.encodeFunctionData("verify", [digest, sig.v, sig.r, sig.s, deployer.address]);
  const tx = await deployer.sendTransaction({ to: address, data });
  const receipt = await tx.wait();

  console.log(`[ecdsa] contract      : ${address}`);
  console.log(`[ecdsa] deploy gas    : ${deployReceipt.gasUsed.toLocaleString()}`);
  console.log(`[ecdsa] recovered     : ${recovered}`);
  console.log(`[ecdsa] valid         : ${valid}`);
  console.log(`[ecdsa] recover est   : ${recoverGas.toLocaleString()} gas`);
  console.log(`[ecdsa] verify est    : ${verifyGas.toLocaleString()} gas`);
  console.log(`[ecdsa] verify tx gas : ${receipt.gasUsed.toLocaleString()} gas`);
}

main().catch((error) => {
  console.error(error);
  process.exitCode = 1;
});
