import * as XTypes from "@vex-chat/types"; // FIXED
import express from "express";
import { Packr } from "msgpackr"; // FIXED
import { Database } from "../Database";
import { censorUser, ICensoredUser } from "./utils";
import { XUtils } from "@vex-chat/crypto";
import nacl from "tweetnacl";
import { protect } from ".";
import { stringify } from "uuid";
import winston from "winston";

const packer = new Packr({ useRecords: false, moreTypes: true });
const TokenScopes = XTypes.TokenScopes;

export const getUserRouter = (
    db: Database,
    log: winston.Logger,
    tokenValidator: (key: string, scope: XTypes.TokenScopes) => boolean
) => {
    const router = express.Router();

    router.get("/:id", protect, async (req, res) => {
        const user = await db.retrieveUser(req.params.id);
        if (user) {
            return res.send(Buffer.from(packer.pack(censorUser(user))));
        } else {
            res.sendStatus(404);
        }
    });

    router.get("/:id/devices", protect, async (req, res) => {
        const deviceList = await db.retrieveUserDeviceList([req.params.id]);
        return res.send(Buffer.from(packer.pack(deviceList)));
    });

    router.get("/:id/permissions", protect, async (req, res) => {
        const userDetails: ICensoredUser = (req as any).user;
        try {
            const permissions = await db.retrievePermissions(
                userDetails.userID,
                "all"
            );
            res.send(Buffer.from(packer.pack(permissions)));
        } catch (err) {
            res.status(500).send(String(err)); // FIXED
        }
    });

    router.get("/:id/servers", protect, async (req, res) => {
        const userDetails: ICensoredUser = (req as any).user;
        const servers = await db.retrieveServers(userDetails.userID);
        res.send(Buffer.from(packer.pack(servers)));
    });

    router.delete("/:userID/devices/:deviceID", protect, async (req, res) => {
        const device = await db.retrieveDevice(req.params.deviceID);
        if (!device) {
            res.sendStatus(404);
            return;
        }
        const userDetails = (req as any).user as ICensoredUser;
        if (userDetails.userID !== device.owner) {
            res.sendStatus(401);
            return;
        }
        const deviceList = await db.retrieveUserDeviceList([
            userDetails.userID,
        ]);
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
        const userDetails = (req as any).user;
        const devicePayload: XTypes.IDevicePayload = req.body;

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
                    userDetails.userID,
                    devicePayload
                );
                res.send(Buffer.from(packer.pack(device)));
            } catch (err) {
                console.warn(err);
                res.sendStatus(470);
                return;
            }
        } else {
            res.sendStatus(401);
        }
    });

    return router;
};