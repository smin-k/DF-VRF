const { ethers, network } = require("hardhat");

async function main() {
  const [deployer] = await ethers.getSigners();
  const chain = await ethers.provider.getNetwork();
  const balance = await ethers.provider.getBalance(deployer.address);

  console.log(`[deuring-arith] network       : ${network.name} (chainId=${chain.chainId})`);
  console.log(`[deuring-arith] deployer      : ${deployer.address}`);
  console.log(`[deuring-arith] balance       : ${ethers.formatEther(balance)} ETH`);

  const Factory = await ethers.getContractFactory("DeuringArithmeticGasBaseline");
  const contract = await Factory.deploy();
  const deployReceipt = await contract.deploymentTransaction().wait();

  // Small affine points on y^2 = x^3 + x over Fp. They are not security
  // parameters; they only keep denominators non-zero for gas profiling.
  const x1 = 1n;
  const y1 = 148780486987152144548468639792905971651836988485316466320491433274783071967n;
  const x2 = 2n;
  const y2 = 430372404739252556353704009725817547032728248803190788684995859142129525134n;

  const rows = [
    ["Fp mul x100", await contract.fpMulLoop.estimateGas(123456789n, 987654321n, 100n)],
    ["Fp inversion", await contract.fpInv.estimateGas(123456789n)],
    ["Fp2 mul x100", await contract.fp2MulLoop.estimateGas(123456789n, 5n, 987654321n, 7n, 100n)],
    ["Fp2 inversion", await contract.fp2Inv.estimateGas(123456789n, 5n)],
    ["EC/Fp2 add", await contract.ecFp2Add.estimateGas([x1, 0n, y1, 0n, x2, 0n, y2, 0n])],
    ["EC/Fp2 double", await contract.ecFp2Double.estimateGas([x1, 0n, y1, 0n])],
    ["EC/Fp2 double x16", await contract.ecFp2DoubleLoop.estimateGas([x1, 0n, y1, 0n], 16n)],
    ["EC/Fp2 double x64", await contract.ecFp2DoubleLoop.estimateGas([x1, 0n, y1, 0n], 64n)],
  ];

  console.log(`[deuring-arith] contract      : ${await contract.getAddress()}`);
  console.log(`[deuring-arith] deploy gas    : ${deployReceipt.gasUsed.toLocaleString()}`);
  console.log(`[deuring-arith] This is a proxy benchmark, not a DeuringVRF verifier.`);
  for (const [label, gas] of rows) {
    console.log(`[deuring-arith] ${label.padEnd(24)} : ${gas.toLocaleString()} gas`);
  }
}

main().catch((error) => {
  console.error(error);
  process.exitCode = 1;
});
