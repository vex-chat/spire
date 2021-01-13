import { XUtils } from "@vex-chat/crypto";
import { XTypes } from "@vex-chat/types";
import express from "express";
import jwt from "jsonwebtoken";
import nacl from "tweetnacl";
import { stringify } from "uuid";
import winston from "winston";
import { EXPIRY_TIME } from ".";

import { Database, hashPassword } from "../Database";
import { censorUser } from "./utils";

const TokenScopes = XTypes.HTTP.TokenScopes;

export const getUserRouter = (
    db: Database,
    log: winston.Logger,
    tokenValidator: (key: string, scope: XTypes.HTTP.TokenScopes) => boolean
) => {
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

        if (typeof password !== "string") {
            res.status(400).send("Password must be a string.");
        }

        const userEntry = await db.retrieveUser(userID);

        if (!userEntry) {
            log.warn("This user doesn't exist.");
            res.sendStatus(404);
            return;
        }

        const salt = XUtils.decodeHex(userEntry.passwordSalt);
        const payloadHash = XUtils.encodeHex(hashPassword(password, salt));

        if (payloadHash !== userEntry.passwordHash) {
            res.sendStatus(401);
            log.info("Wrong password.");
        }

        const deviceEntry = await db.retrieveDevice(deviceID);

        if (!deviceEntry) {
            log.warn("This device doesn't exist.");
            res.sendStatus(404);
            return;
        }

        const userDevices = await db.retrieveUserDeviceList(userID);
        if (userDevices.length === 1) {
            log.warn("User can not delete the only device on their account.");
            res.status(400).send({
                error: "You must have at least one device on your account.",
            });
            return;
        }

        db.deleteDevice(deviceID);
        res.sendStatus(200);
    });

    router.post("/:id/devices", async (req, res) => {
        const devicePayload: XTypes.HTTP.IDevicePayload = req.body;

        const userEntry = await db.retrieveUser(req.params.id);

        if (!userEntry) {
            res.sendStatus(404);
            log.warn("User does not exist.");
            return;
        }

        const salt = XUtils.decodeHex(userEntry.passwordSalt);
        const payloadHash = XUtils.encodeHex(
            hashPassword(devicePayload.password, salt)
        );

        if (payloadHash !== userEntry.passwordHash) {
            res.sendStatus(401);
            return;
        }

        const token = nacl.sign.open(
            XUtils.decodeHex(devicePayload.signed),
            XUtils.decodeHex(devicePayload.signKey)
        );

        if (!token) {
            log.warn("Invalid signature on token.");
            res.sendStatus(400);
            return;
        }

        if (tokenValidator(stringify(token), TokenScopes.Device)) {
            const device = await db.createDevice(
                userEntry.userID,
                devicePayload
            );
            res.send(device);
        } else {
            res.sendStatus(401);
        }
    });

    return router;
};
