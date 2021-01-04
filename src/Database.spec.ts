jest.mock("uuid", () => ({ v4: () => "1480f261c80b8dbce4f4" }));

import { XTypes } from "@vex-chat/types";
import uuid from "uuid";
import winston from "winston";

import { Database } from "./Database";
import { db } from "./db-config";

beforeEach(async () => {
    await db.migrate.latest();
});

afterEach(async () => {
    await db.migrate.rollback();
    await db.destroy();
});

describe("Database", () => {
    const keyID = "1480f261c80b8dbce4f4";

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
                userID: "29c31922344590d153c6",
                publicKey: "3063653038663161393438383933616630353635",
                signature: "3164383165323063626662626265336135323438",
                index: 1,
            };

            const publicKey = Uint8Array.from([
                ...Buffer.from("0ce08f1a948893af0565"),
            ]);
            const signature = Uint8Array.from([
                ...Buffer.from("1d81e20cbfbbbe3a5248"),
            ]);

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
});
