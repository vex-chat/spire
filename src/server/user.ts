import { XUtils } from "@vex-chat/crypto";
import express from "express";
import winston from "winston";

import { Database, hashPassword } from "../Database";
import { censorUser } from "./utils";

export const getUserRouter = (db: Database, log: winston.Logger) => {
    const router = express.Router();

    router.get("/:id", async (req, res) => {
        const user = await db.retrieveUser(req.params.id);

        if (user) {
            return res.send(censorUser(user));
        } else {
            res.sendStatus(404);
        }
    });

    router.get("/:id/devices", async (req, res) => {
        const deviceList = await db.retrieveUserDeviceList(req.params.id);
        return res.send(deviceList);
    });

    router.delete("/:userID/devices/:deviceID", async (req, res) => {
        const { userID, deviceID } = req.params;
        const { password } = req.body;

        const userEntry = await db.retrieveUser(userID);

        if (!userEntry) {
            log.warn("This user doesn't exist.");
            res.sendStatus(404);
            return;
        }

        const deviceEntry = await db.retrieveDevice(deviceID);

        if (!deviceEntry) {
            log.warn("This device doesn't exist.");
            res.sendStatus(404);
        }

        const salt = XUtils.decodeHex(userEntry.passwordSalt);
        const payloadHash = XUtils.encodeHex(hashPassword(password, salt));

        if (payloadHash !== userEntry.passwordHash) {
            res.sendStatus(401);
            log.info("Wrong password.");
        } else {
            db.deleteDevice(deviceID);
            res.sendStatus(200);
        }
    });

    router.post("/:id/authenticate", async (req, res) => {
        const credentials: { username: string; password: string } = req.body;

        try {
            const userEntry = await db.retrieveUser(req.params.id);
            if (!userEntry) {
                res.sendStatus(404);
                log.warn("User does not exist.");
                return;
            }

            const salt = XUtils.decodeHex(userEntry.passwordSalt);
            const payloadHash = XUtils.encodeHex(
                hashPassword(credentials.password, salt)
            );

            if (payloadHash !== userEntry.passwordHash) {
                res.sendStatus(401);
                return;
            }
            // TODO: set a cookie here and use it for WS
            res.sendStatus(200);
        } catch (err) {
            res.sendStatus(500);
        }
    });

    return router;
};
