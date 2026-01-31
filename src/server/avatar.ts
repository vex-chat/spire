import fs from "fs";
import { XUtils } from "@vex-chat/crypto";
import * as XTypes from "@vex-chat/types";
import express from "express";
import FileType from "file-type";
import multer from "multer";
import winston from "winston";
import { ALLOWED_IMAGE_TYPES, protect } from ".";
import { Database } from "../Database";

export const getAvatarRouter = (db: Database, log: winston.Logger) => {
    const router = express.Router();

    router.get("/:userID", async (req, res) => {
            const filePath = "./avatars/" + req.params.userID;

            try {
                // Check if file exists first
                await fs.promises.access(filePath, fs.constants.F_OK);

                // Read file into buffer to check type
                const buffer = await fs.promises.readFile(filePath);
                const typeDetails = await FileType.fromBuffer(buffer);

                if (!res.headersSent) {
                    if (typeDetails) {
                        res.set("Content-type", typeDetails.mime);
                    }
                    res.set("Cache-control", "public, max-age=31536000");

                    // Send the buffer directly instead of streaming to avoid race conditions
                    // with the previous checks in this specific implementation
                    res.send(buffer);
                }
            } catch (e) {
                // File does not exist or cannot be read
                if (!res.headersSent) {
                    res.sendStatus(404);
                }
            }
        });

    router.post("/:userID/json", protect, async (req, res) => {
            const payload: XTypes.IFilePayload = req.body;
            const userDetails = req.user!;
            const deviceDetails = req.device;

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
                fs.writeFile("avatars/" + userDetails.userID, buf, () => {
                    log.info("Wrote new avatar " + userDetails.userID);
                });
                res.sendStatus(200);
            } catch (err) {
                log.warn(String(err));
                res.sendStatus(500);
            }
        });

        router.post(
            "/:userID",
            protect,
            multer().single("avatar"),
            async (req, res) => {
                const userDetails = req.user!;
                const deviceDetails = req.device;

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
                    fs.writeFile(
                        "avatars/" + userDetails.userID,
                        req.file.buffer,
                        () => {
                            log.info("Wrote new avatar " + userDetails.userID);
                        }
                    );
                    res.sendStatus(200);
                } catch (err) {
                    log.warn(String(err));
                    res.sendStatus(500);
                }
            }
        );

    return router;
};
