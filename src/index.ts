import { loadEnv } from "./utils/loadEnv";
import { XChat } from "./XChat";

async function main() {
    // load the environment variables
    loadEnv();
    const xchat = new XChat();
}

main();
