import fs from "fs";
import path from "path";

import { XUtils } from "@vex-chat/crypto";
import { XTypes } from "@vex-chat/types";
import express from "express";
import multer from "multer";
import nacl from "tweetnacl";
import { v4 } from "uuid";
import winston from "winston";

import { Database } from "../Database";

export const getFileRouter = (db: Database, log: winston.Logger) => {
    const router = express.Router();

    router.get("/:id", async (req, res) => {
        const entry = await db.retrieveFile(req.params.id);
        if (!entry) {
            res.sendStatus(404);
        } else {
            const stream = fs.createReadStream("./files/" + entry.fileID);
            stream.on("error", (err) => {
                console.log(err.toString());
                res.send(500);
            });
            stream.pipe(res);
        }
    });

    router.get("/:id/details", async (req, res) => {
        const entry = await db.retrieveFile(req.params.id);
        if (!entry) {
            res.sendStatus(404);
        } else {
            fs.stat(path.resolve("./files/" + entry.fileID), (err, stat) => {
                if (err) {
                    res.sendStatus(500);
                    return;
                }
                res.send({
                    ...entry,
                    size: stat.size,
                    birthtime: stat.birthtime,
                });
            });
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
