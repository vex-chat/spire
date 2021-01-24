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

        const invite = await db.retrieveInvite(req.params.inviteID);
        if (!invite) {
            res.sendStatus(404);
            return;
        }

        if (new Date(invite.expiration).getTime() < Date.now()) {
            res.sendStatus(401);
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

    router.put("/:inviteID", async (req, res) => {
        const invite = await db.retrieveInvite(req.params.inviteID);
        if (!invite) {
            res.sendStatus(404);
            return;
        }
        res.send(invite);
    });

    router.get("/:serverID", protect, async (req, res) => {
        const jwtDetails: ICensoredUser = (req as any).user;

        const permissions = await db.retrievePermissions(
            jwtDetails.userID,
            "server"
        );

        let hasPermission = false;
        for (const permission of permissions) {
            if (
                permission.resourceID === req.params.serverID &&
                permission.powerLevel > POWER_LEVELS.INVITE
            ) {
                hasPermission = true;
            }
        }
        if (!hasPermission) {
            res.sendStatus(401);
            return;
        }

        const inviteList = await db.retrieveServerInvites(req.params.serverID);
        res.send(
            inviteList.filter((invite) => {
                const valid =
                    new Date(Date.now()).getTime() <
                    new Date(invite.expiration).getTime();

                if (!valid) {
                    db.deleteInvite(invite.inviteID);
                }

                return valid;
            })
        );
    });

    router.post("/:serverID", protect, async (req, res) => {
        const jwtDetails: ICensoredUser = (req as any).user;

        const payload: IInvitePayload = req.body;
        const serverEntry = await db.retrieveServer(req.params.serverID);

        if (!serverEntry) {
            res.sendStatus(404);
            return;
        }

        const permissions = await db.retrievePermissions(
            jwtDetails.userID,
            "server"
        );

        let hasPermission = false;
        for (const permission of permissions) {
            if (
                permission.resourceID === req.params.serverID &&
                permission.powerLevel > POWER_LEVELS.INVITE
            ) {
                hasPermission = true;
            }
        }

        if (!hasPermission) {
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
            res.send(invite);
        } else {
            log.warn("Invalid token!");
            res.sendStatus(401);
        }
    });

    return router;
};