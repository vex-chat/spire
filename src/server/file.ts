import fs from "fs";
import path from "path";
import { XUtils } from "@vex-chat/crypto";
import * as XTypes from "@vex-chat/types";
import express from "express";
import multer from "multer";
import { v4 } from "uuid";
import winston from "winston";
import { Packr } from "msgpackr";
import { protect } from ".";
import { Database } from "../Database";

const packer = new Packr({ useRecords: false, moreTypes: true });

export const getFileRouter = (db: Database, log: winston.Logger) => {
    const router = express.Router();

    router.get("/:id", protect, async (req, res) => {
        const entry = await db.retrieveFile(req.params.id);
        if (!entry) {
            res.sendStatus(404);
        } else {
            const stream = fs.createReadStream("./files/" + entry.fileID);
            stream.on("error", (err) => {
                log.error(String(err));
                if (!res.headersSent) res.sendStatus(500);
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
                    Buffer.from(packer.pack({
                        ...entry,
                        size: stat.size,
                        birthtime: stat.birthtime,
                    }))
                );
            });
        }
    });

    router.post("/json", protect, async (req, res) => {
        const deviceDetails = req.device;
        const payload: XTypes.IFilePayload = req.body;

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

        const newFile: XTypes.IFileSQL = {
            fileID: v4(),
            owner: payload.owner,
            nonce: payload.nonce,
        };

        fs.writeFile("files/" + newFile.fileID, buf, () => {
            log.info("Wrote new file " + newFile.fileID);
        });

        await db.createFile(newFile);
        res.send(Buffer.from(packer.pack(newFile)));
    });

    router.post("/", protect, multer().single("file"), async (req, res) => {
        const deviceDetails = req.device;
        const payload = req.body as XTypes.IFilePayload;

        if (!deviceDetails) {
            res.sendStatus(400);
            return;
        }

        if (req.file === undefined) {
            res.sendStatus(400);
            return;
        }

        if (!payload.nonce || payload.nonce === "") {
            res.sendStatus(400);
            return;
        }

        const newFile: XTypes.IFileSQL = {
            fileID: v4(),
            owner: payload.owner,
            nonce: payload.nonce,
        };

        fs.writeFile("files/" + newFile.fileID, req.file.buffer, () => {
            log.info("Wrote new file " + newFile.fileID);
        });

        await db.createFile(newFile);
        res.send(Buffer.from(packer.pack(newFile)));
    });

    return router;
};