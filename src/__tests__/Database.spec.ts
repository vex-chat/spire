jest.mock("uuid", () => ({ v4: () => "93ce482b-a0f2-4f6e-b1df-3aed61073552" }));

import { XUtils } from "@vex-chat/crypto";
import { XTypes } from "@vex-chat/types";
import knex from "knex";
import uuid from "uuid";
import winston from "winston";

import { Database } from "../Database";

import { knexTestConfig } from "../knexfile";

describe("Database", () => {
    const db = knex(knexTestConfig);

    const TABLES = ["oneTimeKeys", "preKeys"];

    // Reusable test data
    const keyID = "de459e05-aa63-4dfa-97b4-ed43d5c7a5f7";
    const userID = "4e67b90f-cbf8-44bc-8ce3-d3b248f033f1";

    const publicKey = XUtils.decodeHex(
        "30c2d0294c1cfdbb73c6b3bbe6010088c2dba8384b04ff2e2b92172431d66b5e"
    );
    const signature = XUtils.decodeHex(
        "dd0665079426c3efcf4dce9b1487e4aca132f8147581b3294c3f23ddd2b4ba8240a10082bd06805d7eb320d91af971da3306e11b60073ccc3d829710f5036004000030c2d0294c1cfdbb73c6b3bbe6010088c2dba8384b04ff2e2b92172431d66b5e"
    );

    const testSQLPreKey: XTypes.SQL.IPreKeys = {
        userID,
        keyID,
        publicKey:
            "30c2d0294c1cfdbb73c6b3bbe6010088c2dba8384b04ff2e2b92172431d66b5e",
        signature:
            "dd0665079426c3efcf4dce9b1487e4aca132f8147581b3294c3f23ddd2b4ba8240a10082bd06805d7eb320d91af971da3306e11b60073ccc3d829710f5036004000030c2d0294c1cfdbb73c6b3bbe6010088c2dba8384b04ff2e2b92172431d66b5e",
        index: 1,
    };

    const testWSPreKey: XTypes.WS.IPreKeys = {
        publicKey,
        signature,
        index: 1,
    };

    beforeAll(() => {
        return db.migrate.latest();
    });

    afterAll(() => {
        return db.destroy();
    });

    beforeEach(() => {
        return Promise.all(
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

            // Act
            const provider = new Database(db);
            await provider.saveOTK(testSQLPreKey.userID, {
                publicKey,
                signature,
                index: 1,
            });

            // Assert
            const oneTimeKeys = await db.select().from("oneTimeKeys");
            expect(oneTimeKeys[0]).toEqual(testSQLPreKey);
        });
    });

    describe("getPreKeys", () => {
        it("returns a preKey by userId if said preKey exists.", async () => {
            // Arrange
            expect.assertions(1); // in case there are async issues the test will fail in ci

            await db("preKeys").insert(testSQLPreKey);

            // Act
            const provider = new Database(db);
            const result = await provider.getPreKeys(userID);

            // Assert
            expect(result).toEqual(testWSPreKey);
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
