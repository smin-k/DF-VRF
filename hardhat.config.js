require("@nomicfoundation/hardhat-toolbox");
const { subtask } = require("hardhat/config");
const { TASK_COMPILE_SOLIDITY_GET_SOURCE_PATHS } = require("hardhat/builtin-tasks/task-names");
require("dotenv").config();

// Solidity files that depend on forge-std, sstore2, or InterfaceVerifier
// are compiled by Foundry only; exclude them from Hardhat compilation.
const FOUNDRY_ONLY = [
  /[/\\]test[/\\]/,           // contracts/test/*.sol
  /ZKNOX_ethfalcon\.sol$/,    // needs sstore2 + ISigVerifier
  /ZKNOX_falcon\.sol$/,       // needs sstore2 + ISigVerifier
  /ZKNOX_epervier\.sol$/,     // needs forge-std/Test.sol
  /ZKNOX_ethepervier\.sol$/,  // needs forge-std/Test.sol
  /ZKNOX_display\.sol$/,      // needs forge-std/Test.sol
  /ZKNOX_PythonSigner\.sol$/, // needs forge-std/Test.sol
  /BaseScript\.sol$/,
  /DeployEPERVIER/,
  /ETHFalcon_Recursive\.sol$/,
  /NTT_Recursive\.sol$/,
  /ZKNOX_falcon_deploy\.sol$/,
];

subtask(TASK_COMPILE_SOLIDITY_GET_SOURCE_PATHS, async (_, __, runSuper) => {
  const paths = await runSuper();
  return paths.filter((p) => !FOUNDRY_ONLY.some((re) => re.test(p)));
});

/** @type import('hardhat/config').HardhatUserConfig */
module.exports = {
  solidity: {
    version: "0.8.25",
    settings: {
      optimizer: { enabled: true, runs: 200 },
    },
  },
  networks: {
    hardhat: { chainId: 31337 },
    localhost: {
      url: process.env.RPC_URL || "http://127.0.0.1:8545",
    },
    sepolia: {
      url: process.env.SEPOLIA_RPC_URL || "",
      accounts: process.env.DEPLOYER_PRIVKEY ? [process.env.DEPLOYER_PRIVKEY] : [],
    },
  },
  paths: {
    sources: "./contracts",
    tests: "./test",
    cache: "./cache",
    artifacts: "./artifacts",
  },
  gasReporter: {
    enabled: process.env.REPORT_GAS === "true",
    currency: "USD",
  },
};
