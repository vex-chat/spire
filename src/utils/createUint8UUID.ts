import { parse as uuidParse, v4 as uuidv4 } from "uuid";

export function createUint8UUID() {
    return new Uint8Array(uuidParse(uuidv4()));
}
