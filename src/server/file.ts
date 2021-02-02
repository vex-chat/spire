import fs from "fs";
import path from "path";

import { XUtils } from "@vex-chat/crypto";
import { XTypes } from "@vex-chat/types";
import express from "express";
import multer from "multer";
import nacl from "tweetnacl";
import { v4 } from "uuid";
import winston from "winston";

import msgpack from "msgpack-lite";
import { protect } from ".";
import { Database } from "../Database";

export const getFileRouter = (db: Database, log: winston.Logger) => {
    const router = express.Router();

    router.get("/:id", protect, async (req, res) => {
        const entry = await db.retrieveFile(req.params.id);
        if (!entry) {
            res.sendStatus(404);
        } else {
            const stream = fs.createReadStream("./files/" + entry.fileID);
            stream.on("error", (err) => {
                log.error(err.toString());
                res.sendStatus(500);
            });
            stream.pipe(res);
        }
    });

    router.get("/:id/details", protect, async (req, res) => {
        const entry = await db.retrieveFile(req.params.id);
        if (!entry) {
            res.sendStatus(404);
        } else {
            fs.stat(path.resolve("./files/" + entry.fileID), (err, stat) => {
                if (err) {
                    res.sendStatus(500);
                    return;
                }
                res.set("Cache-control", "public, max-age=31536000");
                res.send(
                    msgpack.encode({
                        ...entry,
                        size: stat.size,
                        birthtime: stat.birthtime,
                    })
                );
            });
        }
    });

    router.post("/json", protect, async (req, res) => {
        const deviceDetails: XTypes.SQL.IDevice | undefined = (req as any)
            .device;
        const payload: XTypes.HTTP.IFilePayload = req.body;

        if (!deviceDetails) {
            res.sendStatus(401);
            return;
        }

        if (payload.nonce === "") {
            res.sendStatus(400);
            return;
        }

        if (!payload.file) {
            res.sendStatus(400);
            return;
        }

        const buf = Buffer.from(XUtils.decodeBase64(payload.file));

        const newFile: XTypes.SQL.IFile = {
            fileID: v4(),
            owner: payload.owner,
            nonce: payload.nonce,
        };

        // write the file to disk
        fs.writeFile("files/" + newFile.fileID, buf, () => {
            log.info("Wrote new file " + newFile.fileID);
        });

        await db.createFile(newFile);
        res.send(msgpack.encode(newFile));
    });

    router.post("/", protect, multer().single("file"), async (req, res) => {
        const deviceDetails: XTypes.SQL.IDevice | undefined = (req as any)
            .device;
        const payload: XTypes.HTTP.IFilePayload = req.body;

        if (!deviceDetails) {
            res.sendStatus(400);
            return;
        }

        if (req.file === undefined) {
            res.sendStatus(400);
            return;
        }

        if (payload.nonce === "") {
            res.sendStatus(400);
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
        res.send(msgpack.encode(newFile));
    });

    return router;
};
