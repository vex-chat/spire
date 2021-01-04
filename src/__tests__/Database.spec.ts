jest.mock("uuid", () => ({ v4: () => "1480f261c80b8dbce4f4" }));

import { XTypes } from "@vex-chat/types";
import uuid from "uuid";
import winston from "winston";

import { Database } from "../Database";
import { db } from "../db-config";

beforeAll(async () => {
    await db.migrate.latest();
});

afterAll(async () => {
    await db.destroy();
});

describe("Database", () => {
    const TABLES = ["oneTimeKeys", "preKeys"];

    // Reusable test data
    const keyID = "1480f261c80b8dbce4f4";
    const userID = "29c31922344590d153c6";

    const publicKey = Uint8Array.from([...Buffer.from("0ce08f1a948893af0565")]);
    const signature = Uint8Array.from([...Buffer.from("1d81e20cbfbbbe3a5248")]);

    beforeEach(async () => {
        await Promise.all(
            TABLES.map(async (table) => {
                await db(table).truncate();
            })
        );
    });

    describe("saveOTK", () => {
        it("takes a userId and one time key, adds a keyId and saves it to oneTimeKey table", async () => {
            // Arrange
            expect.assertions(1); // in case there are async issues the test will fail in ci

            const v4Spy = jest.spyOn(uuid, "v4").mockReturnValue(keyID);
            const createLoggerSpy = jest
                .spyOn(winston, "createLogger")
                .mockReturnValueOnce(({} as unknown) as winston.Logger);

            const expectedOTK: XTypes.SQL.IPreKeys = {
                keyID,
                userID,
                publicKey: "3063653038663161393438383933616630353635",
                signature: "3164383165323063626662626265336135323438",
                index: 1,
            };

            // Act
            const provider = new Database(db);
            await provider.saveOTK(expectedOTK.userID, {
                publicKey,
                signature,
                index: 1,
            });

            // Assert
            const oneTimeKeys = await db
                .select()
                .from<XTypes.WS.IPreKeys>("oneTimeKeys");
            expect(oneTimeKeys[0]).toEqual(expectedOTK);
        });
    });

    describe("getPreKeys", () => {
        it("returns a preKey by userId if said preKey exists.", async () => {
            // Arrange
            expect.assertions(1); // in case there are async issues the test will fail in ci

            const testPreKey: XTypes.SQL.IPreKeys = {
                userID,
                keyID,
                publicKey: "0ce08f1a948893af0565",
                signature: "1d81e20cbfbbbe3a5248",
                index: 1,
            };

            const expectedPreKey: XTypes.WS.IPreKeys = {
                publicKey: new Uint8Array([
                    12,
                    224,
                    143,
                    26,
                    148,
                    136,
                    147,
                    175,
                    5,
                    101,
                ]),
                signature: new Uint8Array([
                    29,
                    129,
                    226,
                    12,
                    191,
                    187,
                    190,
                    58,
                    82,
                    72,
                ]),
                index: 1,
            };

            await db("preKeys").insert(testPreKey);

            // Act
            const provider = new Database(db);
            const result = await provider.getPreKeys(userID);

            // Assert
            expect(result).toEqual(expectedPreKey);
        });

        it("return null if there are no preKeys with userId param", async () => {
            // Arrange
            expect.assertions(1); // in case there are async issues the test will fail in ci

            // Act
            const provider = new Database(db);
            const result = await provider.getPreKeys(userID);

            // Assert
            expect(result).toBeNull();
        });
    });
});
