import { Spire } from "./Spire";
import { loadEnv } from "./utils/loadEnv";

async function main() {
    // load the environment variables
    loadEnv();
    const server = new Spire({ logLevel: "info", selfSigned: true });
}

main();
