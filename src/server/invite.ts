import fs from "fs";
import path from "path";

import { XUtils } from "@vex-chat/crypto";
import { XTypes } from "@vex-chat/types";
import express from "express";
import FileType from "file-type";
import multer from "multer";
import nacl from "tweetnacl";
import * as uuid from "uuid";
import winston from "winston";

import { POWER_LEVELS } from "../ClientManager";
import { Database } from "../Database";

import { ICensoredUser } from "./utils";

export const getInviteRouter = (db: Database, log: winston.Logger) => {
    const router = express.Router();

    router.post("/:serverID", async (req, res) => {
        const jwtDetails: ICensoredUser = (req as any).user;

        const payload: XTypes.HTTP.IFilePayload = req.body;
        const serverEntry = await db.retrieveServer(req.params.serverID);

        if (!serverEntry) {
            res.sendStatus(404);
            return;
        }

        const permissions = await db.retrievePermissionsByResourceID(
            req.params.serverID
        );

        let hasPerm = false;
        for (const permission of permissions) {
            if (
                permission.resourceID === req.params.serverID &&
                permission.powerLevel > POWER_LEVELS.INVITE
            ) {
                hasPerm = true;
            }
        }

        if (!hasPerm) {
            res.sendStatus(401);
            return;
        }

        const devices = await db.retrieveUserDeviceList([jwtDetails.userID]);
        if (!devices) {
            res.sendStatus(401);
            return;
        }

        let token: Uint8Array | null = null;
        for (const device of devices) {
            const verified = nacl.sign.open(
                XUtils.decodeHex(payload.signed),
                XUtils.decodeHex(device.signKey)
            );
            if (verified) {
                token = verified;
            }
        }
        if (!token) {
            log.warn("Bad signature on token.");
            res.sendStatus(401);
            return;
        }

        res.send({ invite: uuid.v4() });
    });

    return router;
};
