import path from "path";
import fs from "fs";

import { XUtils } from "@vex-chat/crypto";
import { XTypes } from "@vex-chat/types";
import express from "express";
import winston from "winston";
import FileType from "file-type";
import nacl from "tweetnacl";
import multer from "multer";

import { Database } from "../Database";

export const getAvatarRouter = (db: Database, log: winston.Logger) => {
    const router = express.Router();

    router.get("/:userID", async (req, res) => {
        fs.readFile(
            path.resolve("./avatars/" + req.params.userID),
            undefined,
            async (err, file) => {
                if (err) {
                    log.error("error reading file");
                    log.error(err);
                    res.sendStatus(404);
                } else {
                    const typeDetails = await FileType.fromBuffer(file);
                    if (typeDetails) {
                        res.set("Content-type", typeDetails.mime);
                    }
                    res.send(file);
                }
            }
        );
    });

    router.post("/:userID", multer().single("avatar"), async (req, res) => {
        const payload: XTypes.HTTP.IFilePayload = req.body;
        const userEntry = await db.retrieveUser(req.params.userID);

        if (!userEntry) {
            res.sendStatus(404);
            return;
        }

        const devices = await db.retrieveUserDeviceList(req.params.userID);

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

        try {
            // write the file to disk
            fs.writeFile("avatars/" + userEntry.userID, req.file.buffer, () => {
                log.info("Wrote new avatar " + userEntry.userID);
            });
            res.sendStatus(200);
        } catch (err) {
            log.warn(err);
            res.sendStatus(500);
        }
    });

    return router;
};
