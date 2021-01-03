import { Spire } from "./Spire";
import { loadEnv } from "./utils/loadEnv";

async function main() {
    // load the environment variables
    loadEnv();
    // const server = new Spire({
    //     logLevel: "info",
    // });
    const spire = new Spire({
        dbType: "sqlite3mem",
        logLevel: "info",
    });
}

main();
