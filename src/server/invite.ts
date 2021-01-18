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

import parseDuration from "parse-duration";

import { POWER_LEVELS } from "../ClientManager";
import { Database } from "../Database";

import { protect } from ".";
import { ICensoredUser } from "./utils";

interface IInvitePayload {
    serverID: string;
    signed: string;
    duration: string;
}

export const getInviteRouter = (
    db: Database,
    log: winston.Logger,
    tokenValidator: (key: string, scope: XTypes.HTTP.TokenScopes) => boolean,
    notify: (
        userID: string,
        event: string,
        transmissionID: string,
        data?: any,
        deviceID?: string
    ) => void
) => {
    const router = express.Router();
    router.patch("/:inviteID", protect, async (req, res) => {
        const jwtDetails: ICensoredUser = (req as any).user;
        console.log(req.params.inviteID);

        const invite = await db.retrieveInvite(req.params.inviteID);
        if (!invite) {
            res.sendStatus(404);
            return;
        }
        const permission = await db.createPermission(
            jwtDetails.userID,
            "server",
            invite.serverID,
            0
        );
        res.send(permission);
        notify(jwtDetails.userID, "permission", uuid.v4(), permission);
    });

    router.post("/:serverID", protect, async (req, res) => {
        const jwtDetails: ICensoredUser = (req as any).user;

        const payload: IInvitePayload = req.body;
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
                permission.userID === jwtDetails.userID &&
                permission.resourceID === req.params.serverID &&
                permission.powerLevel > POWER_LEVELS.INVITE
            ) {
                hasPerm = true;
            }
        }

        if (!hasPerm) {
            log.warn("No permission!");
            res.sendStatus(401);
            return;
        }

        const devices = await db.retrieveUserDeviceList([jwtDetails.userID]);
        if (!devices) {
            log.warn("No devices!");
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

        if (
            tokenValidator(
                uuid.stringify(token),
                XTypes.HTTP.TokenScopes.Invite
            )
        ) {
            const duration = parseDuration(payload.duration, "ms");

            if (!duration) {
                res.sendStatus(400);
                return;
            }

            const expires = new Date(Date.now() + duration);

            const invite = await db.createInvite(
                uuid.stringify(token),
                serverEntry.serverID,
                jwtDetails.userID,
                expires.toString()
            );
            res.send({ invite });
        } else {
            log.warn("Invalid token!");
            res.sendStatus(401);
        }
    });

    return router;
};
