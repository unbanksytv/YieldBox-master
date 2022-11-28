import { HardhatUserConfig, task } from "hardhat/config"
import "@nomiclabs/hardhat-ethers"
import "@nomiclabs/hardhat-etherscan"
import "@nomiclabs/hardhat-waffle"
import "@typechain/hardhat"
import "hardhat-gas-reporter"
import "hardhat-deploy"
import "solidity-coverage"
import "@boringcrypto/hardhat-framework"
import { ethers, BigNumber } from "ethers"
import requestSync from "sync-request"
import "hardhat-tracer"

if (process.env.DOTENV_PATH) {
    console.log("Using custom .env path:", process.env.DOTENV_PATH)
    require("dotenv").config({ path: process.env.DOTENV_PATH })
} else {
    require("dotenv").config()
}

// This is a sample Hardhat task. To learn how to create your own go to
// https://hardhat.org/guides/create-task.html
task("accounts", "Prints the list of accounts", async (taskArgs, hre) => {
    const accounts = await hre.ethers.getSigners()

    for (const account of accounts) {
        console.log(account.address)
    }

    console.log(await hre.getNamedAccounts())
})

// You need to export an object to set up your config
// Go to https://hardhat.org/config/ to learn more

const last_block =
    process.env.ALCHEMY_API_KEY && false
        ? BigNumber.from(
              JSON.parse(
                  requestSync("GET", "https://api.etherscan.io/api?module=proxy&action=eth_blockNumber&apikey=YourApiKeyToken").body as string
              ).result
          )
        : BigNumber.from(14333352)

console.log(
    process.env.ALCHEMY_API_KEY
        ? "Forking from block " + (last_block.toNumber() - 6).toString()
        : "Please add your Alchemy key to the ALCHEMY_API_KEY environment variable or to .env"
)

const config: HardhatUserConfig = {
    solidity: {
        version: "0.8.9",
        settings: {
            optimizer: {
                enabled: true,
                runs: 50000,
            },
        },
    },
    networks: {
        hardhat: Object.assign(
            {
                live: false,
                blockGasLimit: 30_000_000,
                allowUnlimitedContractSize: true,
            },
            process.env.ALCHEMY_API_KEY
                ? {
                      forking: {
                          url: `https://eth-mainnet.alchemyapi.io/v2/${process.env.ALCHEMY_API_KEY}`,
                          blockNumber: last_block.toNumber() - 6,
                      },
                  }
                : {}
        ),
    },
    namedAccounts: {
        deployer: { default: 0 },
        alice: { default: 1 },
        bob: { default: 2 },
        carol: { default: 3 },
        dave: { default: 4 },
        eve: { default: 5 },
        frank: { default: 6 },
        grace: { default: 7 },
    },
    gasReporter: {
        enabled: true,
        currency: "USD",
        outputFile: "gas_report.txt",
        noColors: true,
        showMethodSig: true,
        coinmarketcap: process.env.COINMARKETCAP_API_KEY,
    },
    etherscan: {
        apiKey: process.env.ETHERSCAN_API_KEY,
    },
}

export default config
