import path from "path";
import fs from "fs";

import { XUtils } from "@vex-chat/crypto";
import { XTypes } from "@vex-chat/types";
import express from "express";
import winston from "winston";
import FileType from "file-type";
import nacl from "tweetnacl";
import multer from "multer";
import { v4 } from "uuid";

import { Database } from "../Database";

export const getFileRouter = (db: Database, log: winston.Logger) => {
    const router = express.Router();

    router.get("/:id", async (req, res) => {
        const entry = await db.retrieveFile(req.params.id);
        if (!entry) {
            res.sendStatus(404);
        } else {
            fs.readFile(
                path.resolve("./files/" + entry.fileID),
                undefined,
                async (err, file) => {
                    if (err) {
                        log.error("error reading file");
                        log.error(err);
                        res.sendStatus(500);
                    } else {
                        const typeDetails = await FileType.fromBuffer(file);
                        // TODO: fix this as well, its bloating the size
                        const resp: XTypes.HTTP.IFileResponse = {
                            details: entry,
                            data: file,
                        };
                        if (typeDetails) {
                            res.set("Content-type", typeDetails.mime);
                        }
                        res.send(resp);
                    }
                }
            );
        }
    });

    router.post("/", multer().single("file"), async (req, res) => {
        const payload: XTypes.HTTP.IFilePayload = req.body;

        if (payload.nonce === "") {
            res.sendStatus(400);
            return;
        }

        const deviceEntry = await db.retrieveDevice(payload.owner);
        if (!deviceEntry) {
            log.warn("No device found.");
            res.send(400);
            return;
        }

        const devices = await db.retrieveUserDeviceList(deviceEntry.owner);

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

        const newFile: XTypes.SQL.IFile = {
            fileID: v4(),
            owner: payload.owner,
            nonce: payload.nonce,
        };

        // write the file to disk
        fs.writeFile("files/" + newFile.fileID, req.file.buffer, () => {
            log.info("Wrote new file " + newFile.fileID);
        });

        await db.createFile(newFile);
        res.send(newFile);
    });

    return router;
};
