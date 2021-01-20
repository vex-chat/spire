import fs from "fs";
import path from "path";

import { XUtils } from "@vex-chat/crypto";
import { XTypes } from "@vex-chat/types";
import express from "express";
import FileType from "file-type";
import multer from "multer";
import nacl from "tweetnacl";
import winston from "winston";

import { Database } from "../Database";
import { protect } from ".";

export const getAvatarRouter = (db: Database, log: winston.Logger) => {
    const router = express.Router();

    router.get("/:userID", async (req, res) => {
        const stream = fs.createReadStream("./avatars/" + req.params.userID);
        stream.on("error", (err) => {
            // log.error(err.toString());
            res.sendStatus(404);
        });

        const typeDetails = await FileType.fromStream(stream);
        if (typeDetails) {
            res.set("Content-type", typeDetails.mime);
        }

        res.set("Cache-control", "public, max-age=31536000");
        const stream2 = fs.createReadStream("./avatars/" + req.params.userID);
        stream2.on("error", (err) => {
            log.error(err.toString());
            res.sendStatus(500);
        });
        stream2.pipe(res);
    });

    router.post("/:userID/json", protect, async (req, res) => {
        const payload: XTypes.HTTP.IFilePayload = req.body;
        const userEntry = await db.retrieveUser(req.params.userID);
        console.log("REQ.BODY", JSON.stringify(payload));

        if (!payload.file) {
            console.warn("MISSING FILE");
            res.sendStatus(400);
            return;
        }

        if (!userEntry) {
            res.sendStatus(404);
            return;
        }

        const devices = await db.retrieveUserDeviceList([req.params.userID]);

        const buf = Buffer.from(XUtils.decodeBase64(payload.file));

        const mimeType = await FileType.fromBuffer(buf);

        const allowedTypes = [
            "image/jpeg",
            "image/png",
            "image/gif",
            "image/apng",
            "image/avif",
        ];

        if (!allowedTypes.includes(mimeType?.mime || "no/type")) {
            res.status(400).send({
                error:
                    "Unsupported file type. Expected jpeg, png, gif, apng, avif, or svg but received " +
                    mimeType?.ext,
            });
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

        try {
            // write the file to disk
            fs.writeFile("avatars/" + userEntry.userID, buf, () => {
                log.info("Wrote new avatar " + userEntry.userID);
            });
            res.sendStatus(200);
        } catch (err) {
            log.warn(err);
            res.sendStatus(500);
        }
    });

    router.post("/:userID", multer().single("avatar"), async (req, res) => {
        const payload: XTypes.HTTP.IFilePayload = req.body;
        const userEntry = await db.retrieveUser(req.params.userID);

        if (!req.file) {
            console.warn("MISSING FILE");
            res.sendStatus(400);
            return;
        }

        if (!userEntry) {
            res.sendStatus(404);
            return;
        }

        const devices = await db.retrieveUserDeviceList([req.params.userID]);

        const mimeType = await FileType.fromBuffer(req.file.buffer);

        const allowedTypes = [
            "image/jpeg",
            "image/png",
            "image/gif",
            "image/apng",
            "image/avif",
        ];

        if (!allowedTypes.includes(mimeType?.mime || "no/type")) {
            res.status(400).send({
                error:
                    "Unsupported file type. Expected jpeg, png, gif, apng, avif, or svg but received " +
                    mimeType?.ext,
            });
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
