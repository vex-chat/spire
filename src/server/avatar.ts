import fs from "fs";

import { XUtils } from "@vex-chat/crypto";
import { XTypes } from "@vex-chat/types";
import express from "express";
import FileType from "file-type";
import multer from "multer";
import nacl from "tweetnacl";
import winston from "winston";

import { ALLOWED_IMAGE_TYPES, protect } from ".";
import { Database } from "../Database";
import { ICensoredUser } from "./utils";

export const getAvatarRouter = (db: Database, log: winston.Logger) => {
    const router = express.Router();

    router.get("/:userID", async (req, res) => {
        const filePath = "./avatars/" + req.params.userID;

        // Check if file exists first to avoid unhandled promise rejection
        if (!fs.existsSync(filePath)) {
            res.sendStatus(404);
            return;
        }

        try {
            const stream = fs.createReadStream(filePath);
            const typeDetails = await FileType.fromStream(stream);
            if (typeDetails) {
                res.set("Content-type", typeDetails.mime);
            }

            res.set("Cache-control", "public, max-age=31536000");
            const stream2 = fs.createReadStream(filePath);
            stream2.on("error", (err) => {
                log.error(err.toString());
                if (!res.headersSent) {
                    res.sendStatus(500);
                }
            });
            stream2.pipe(res);
        } catch (err) {
            log.error("Error serving avatar: " + (err as Error).toString());
            if (!res.headersSent) {
                res.sendStatus(500);
            }
        }
    });

    router.post("/:userID/json", protect, async (req, res) => {
        const payload: XTypes.HTTP.IFilePayload = req.body;
        const userDetails: ICensoredUser = (req as any).user;
        const deviceDetails: XTypes.SQL.IDevice | undefined = (req as any)
            .device;

        if (!deviceDetails) {
            res.sendStatus(401);
            return;
        }

        if (!payload.file) {
            console.warn("MISSING FILE");
            res.sendStatus(400);
            return;
        }

        const buf = Buffer.from(XUtils.decodeBase64(payload.file));
        const mimeType = await FileType.fromBuffer(buf);
        if (!ALLOWED_IMAGE_TYPES.includes(mimeType?.mime || "no/type")) {
            res.status(400).send({
                error:
                    "Unsupported file type. Expected jpeg, png, gif, apng, avif, or svg but received " +
                    mimeType?.ext,
            });
            return;
        }

        try {
            // write the file to disk
            fs.writeFile("avatars/" + userDetails.userID, buf, () => {
                log.info("Wrote new avatar " + userDetails.userID);
            });
            res.sendStatus(200);
        } catch (err) {
            log.warn(err);
            res.sendStatus(500);
        }
    });

    router.post(
        "/:userID",
        protect,
        multer().single("avatar"),
        async (req, res) => {
            const userDetails: ICensoredUser = (req as any).user;
            const deviceDetails: XTypes.SQL.IDevice | undefined = (req as any)
                .device;

            if (!deviceDetails) {
                res.sendStatus(401);
                return;
            }

            if (!req.file) {
                console.warn("MISSING FILE");
                res.sendStatus(400);
                return;
            }

            const mimeType = await FileType.fromBuffer(req.file.buffer);
            if (!ALLOWED_IMAGE_TYPES.includes(mimeType?.mime || "no/type")) {
                res.status(400).send({
                    error:
                        "Unsupported file type. Expected jpeg, png, gif, apng, avif, or svg but received " +
                        mimeType?.ext,
                });
                return;
            }

            try {
                // write the file to disk
                fs.writeFile(
                    "avatars/" + userDetails.userID,
                    req.file.buffer,
                    () => {
                        log.info("Wrote new avatar " + userDetails.userID);
                    }
                );
                res.sendStatus(200);
            } catch (err) {
                log.warn(err);
                res.sendStatus(500);
            }
        }
    );

    return router;
};