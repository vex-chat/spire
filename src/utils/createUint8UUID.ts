import { parse as uuidParse, v4 as uuidv4 } from "uuid";

export function createUint8UUID() {
    return uuidToUint8(uuidv4());
}

export function uuidToUint8(uuid: string) {
    return new Uint8Array(uuidParse(uuid));
}
