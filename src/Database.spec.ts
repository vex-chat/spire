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
                userID: "36913cd5-8285-4cd0-8ceb-8b5769c044c8",
                publicKey: "9495c2e47685a26e753c03acb5ba7da202408a2edb320c1ac4291d6cc7b9d973",
                signature: "503ef6f60ecc807177dbbb86f5ed7a071ba9cf0f268eb312e669f501b36afa3ace88a96c7b37ff13802cd3c6fefce19286e9f4f3216e3da0d50a22118242960a00019495c2e47685a26e753c03acb5ba7da202408a2edb320c1ac4291d6cc7b9d973",
                index: 1,
            };

            const publicKey = Uint8Array.from([
                ...Buffer.from(expectedOTK.publicKey),
            ]);
            const signature = Uint8Array.from([
                ...Buffer.from(expectedOTK.signature),
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
