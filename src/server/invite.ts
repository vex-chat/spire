import * as XTypes from "@vex-chat/types";
import express, { Router } from "express";
import { Packr } from "msgpackr";
import * as uuid from "uuid";
import winston from "winston";
import { Database } from "../Database";
import { protect } from ".";

const packer = new Packr({ useRecords: false, moreTypes: true });

export const getInviteRouter = (
    db: Database,
    log: winston.Logger,
    tokenValidator: (key: string, scope: XTypes.TokenScopes) => boolean,
    notify: (
        userID: string,
        event: string,
        transmissionID: string,
        data?: any,
        deviceID?: string
    ) => void
): Router => {
    const router = express.Router();

    router.patch("/:inviteID", protect, async (req, res) => {
        const userDetails = req.user!;

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
            userDetails.userID,
            "server",
            invite.serverID,
            0
        );
        res.send(Buffer.from(packer.pack(permission)));
        notify(userDetails.userID, "permission", uuid.v4(), permission);
    });

    router.get("/:inviteID", protect, async (req, res) => {
        const invite = await db.retrieveInvite(req.params.inviteID);
        if (!invite) {
            res.sendStatus(404);
            return;
        }
        res.send(Buffer.from(packer.pack(invite)));
    });

    return router;
};