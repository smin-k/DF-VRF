const { ethers, network } = require("hardhat");
const data = require("vrf-solidity/test/data.json");

async function sendFunctionTx(deployer, contract, name, args, gasLimit = undefined) {
  const encoded = contract.interface.encodeFunctionData(name, args);
  const tx = await deployer.sendTransaction({
    to: await contract.getAddress(),
    data: encoded,
    ...(gasLimit ? { gasLimit } : {}),
  });
  return tx.wait();
}

async function main() {
  const [deployer] = await ethers.getSigners();
  const chain = await ethers.provider.getNetwork();
  const balance = await ethers.provider.getBalance(deployer.address);

  console.log(`[vrf-baseline] network       : ${network.name} (chainId=${chain.chainId})`);
  console.log(`[vrf-baseline] deployer      : ${deployer.address}`);
  console.log(`[vrf-baseline] balance       : ${ethers.formatEther(balance)} ETH`);

  const Factory = await ethers.getContractFactory("WitnetVRFGasBaseline");
  const contract = await Factory.deploy();
  const deployReceipt = await contract.deploymentTransaction().wait();
  const address = await contract.getAddress();

  const full = data.verify.valid[0];
  const publicKey = Array.from(await contract.decodePoint.staticCall(full.pub));
  const proof = Array.from(await contract.decodeProof.staticCall(full.pi));
  const message = full.message;
  const fullValid = await contract.verify.staticCall(publicKey, proof, message);
  const fullGas = await contract.verify.estimateGas(publicKey, proof, message);
  const fullReceipt = await sendFunctionTx(deployer, contract, "verify", [publicKey, proof, message], fullGas + 500_000n);
  const hPoint = Array.from(await contract.hashToTryAndIncrement.staticCall(publicKey, message));
  const hashToCurveGas = await contract.hashToTryAndIncrement.estimateGas(publicKey, message);

  const fast = data.fastVerify.valid[0];
  const fastPublicKey = [fast.publicKey.x, fast.publicKey.y];
  const fastProof = Array.from(await contract.decodeProof.staticCall(fast.pi));
  const uPoint = [fast.uPoint.x, fast.uPoint.y];
  const vComponents = [
    fast.vComponents.sH.x,
    fast.vComponents.sH.y,
    fast.vComponents.cGamma.x,
    fast.vComponents.cGamma.y,
  ];
  const fastValid = await contract.fastVerify.staticCall(fastPublicKey, fastProof, fast.message, uPoint, vComponents);
  const fastGas = await contract.fastVerify.estimateGas(fastPublicKey, fastProof, fast.message, uPoint, vComponents);
  const fastReceipt = await sendFunctionTx(
    deployer,
    contract,
    "fastVerify",
    [fastPublicKey, fastProof, fast.message, uPoint, vComponents],
    fastGas + 500_000n
  );

  const paramsGas = await contract.computeFastVerifyParams.estimateGas(publicKey, proof, message);
  const paramsReceipt = await sendFunctionTx(
    deployer,
    contract,
    "computeFastVerifyParams",
    [publicKey, proof, message],
    paramsGas + 500_000n
  );
  const gammaGas = await contract.gammaToHash.estimateGas(proof[0], proof[1]);
  const gammaReceipt = await sendFunctionTx(deployer, contract, "gammaToHash", [proof[0], proof[1]], gammaGas + 100_000n);
  const ecMulSubMulBaseGas = await contract.ecMulSubMul.estimateGas(
    proof[3],
    "0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798",
    "0x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8",
    proof[2],
    publicKey[0],
    publicKey[1]
  );
  const ecMulSubMulHashGas = await contract.ecMulSubMul.estimateGas(
    proof[3],
    hPoint[0],
    hPoint[1],
    proof[2],
    proof[0],
    proof[1]
  );
  const hashPointsGas = await contract.hashPoints.estimateGas(
    hPoint[0],
    hPoint[1],
    proof[0],
    proof[1],
    uPoint[0],
    uPoint[1],
    vComponents[0],
    vComponents[1]
  );

  console.log(`[vrf-baseline] contract      : ${address}`);
  console.log(`[vrf-baseline] deploy gas    : ${deployReceipt.gasUsed.toLocaleString()}`);
  console.log(`[vrf-baseline] ECVRF verify valid      : ${fullValid}`);
  console.log(`[vrf-baseline] ECVRF verify estimate   : ${fullGas.toLocaleString()} gas`);
  console.log(`[vrf-baseline] ECVRF verify tx gas     : ${fullReceipt.gasUsed.toLocaleString()} gas`);
  console.log(`[vrf-baseline] hashToTryIncrement est  : ${hashToCurveGas.toLocaleString()} gas`);
  console.log(`[vrf-baseline] ecMulSubMul U est       : ${ecMulSubMulBaseGas.toLocaleString()} gas`);
  console.log(`[vrf-baseline] ecMulSubMul V est       : ${ecMulSubMulHashGas.toLocaleString()} gas`);
  console.log(`[vrf-baseline] hashPoints est          : ${hashPointsGas.toLocaleString()} gas`);
  console.log(`[vrf-baseline] ECVRF fastVerify valid  : ${fastValid}`);
  console.log(`[vrf-baseline] ECVRF fastVerify est    : ${fastGas.toLocaleString()} gas`);
  console.log(`[vrf-baseline] ECVRF fastVerify tx gas : ${fastReceipt.gasUsed.toLocaleString()} gas`);
  console.log(`[vrf-baseline] computeFast params tx   : ${paramsReceipt.gasUsed.toLocaleString()} gas`);
  console.log(`[vrf-baseline] gammaToHash tx          : ${gammaReceipt.gasUsed.toLocaleString()} gas`);
}

main().catch((error) => {
  console.error(error);
  process.exitCode = 1;
});
