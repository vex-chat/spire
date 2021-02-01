import { XUtils } from "@vex-chat/crypto";
import { XTypes } from "@vex-chat/types";
import express from "express";
import jwt from "jsonwebtoken";
import nacl from "tweetnacl";
import { stringify } from "uuid";
import winston from "winston";
import { EXPIRY_TIME, protect } from ".";

import { Database, hashPassword } from "../Database";
import { censorUser, ICensoredUser } from "./utils";

const TokenScopes = XTypes.HTTP.TokenScopes;

export const getUserRouter = (
    db: Database,
    log: winston.Logger,
    tokenValidator: (key: string, scope: XTypes.HTTP.TokenScopes) => boolean
) => {
    const router = express.Router();

    router.get("/:id", protect, async (req, res) => {
        const user = await db.retrieveUser(req.params.id);

        if (user) {
            return res.send(censorUser(user));
        } else {
            res.sendStatus(404);
        }
    });

    router.get("/:id/devices", protect, async (req, res) => {
        const deviceList = await db.retrieveUserDeviceList([req.params.id]);
        return res.send(deviceList);
    });

    router.get("/:id/permissions", protect, async (req, res) => {
        const jwtDetails: ICensoredUser = (req as any).user;
        try {
            const permissions = await db.retrievePermissions(
                jwtDetails.userID,
                "all"
            );
            res.send(permissions);
        } catch (err) {
            res.status(500).send(err.toString());
        }
    });

    router.get("/:id/servers", protect, async (req, res) => {
        const jwtDetails: ICensoredUser = (req as any).user;
        const servers = await db.retrieveServers(jwtDetails.userID);
        res.send(servers);
    });

    router.delete("/:userID/devices/:deviceID", protect, async (req, res) => {
        const device = await db.retrieveDevice(req.params.deviceID);

        if (!device) {
            res.sendStatus(404);
            return;
        }
        const jwtDetails = (req as any).user as ICensoredUser;
        if (jwtDetails.userID !== device.owner) {
            res.sendStatus(401);
            return;
        }
        const deviceList = await db.retrieveUserDeviceList([jwtDetails.userID]);
        if (deviceList.length === 1) {
            res.status(400).send({
                error: "You can't delete your last device.",
            });
            return;
        }

        await db.deleteDevice(device.deviceID);
        res.sendStatus(200);
    });

    router.post("/:id/devices", protect, async (req, res) => {
        const devicePayload: XTypes.HTTP.IDevicePayload = req.body;

        const userEntry = await db.retrieveUser(req.params.id);

        if (!userEntry) {
            res.sendStatus(404);
            log.warn("User does not exist.");
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
            try {
                const device = await db.createDevice(
                    userEntry.userID,
                    devicePayload
                );
                res.send(device);
            } catch (err) {
                console.warn(err);
                // failed registration due to signkey being taken
                res.sendStatus(470);
                return;
            }
        } else {
            res.sendStatus(401);
        }
    });

    return router;
};
