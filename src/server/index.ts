import path from "path";
import fs from "fs";

import { XUtils } from "@vex-chat/crypto";
import { XTypes } from "@vex-chat/types";
import cors from "cors";
import express from "express";
import expressWs from "express-ws";
import FileType from "file-type";

import helmet from "helmet";
import morgan from "morgan";
import multer from "multer";
import nacl from "tweetnacl";
import * as uuid from "uuid";
import winston from "winston";

import { Database } from "../Database";
import { getUserRouter } from "./user";

// expiry of regkeys
export const EXPIRY_TIME = 1000 * 60 * 5;

// 3-19 chars long

const directories = ["files", "avatars"];
for (const dir of directories) {
    if (!fs.existsSync(dir)) {
        fs.mkdirSync(dir);
    }
}

export const initApp = (
    api: expressWs.Application,
    db: Database,
    log: winston.Logger,
    tokenValidator: (key: string, scope: XTypes.HTTP.TokenScopes) => boolean
) => {
    // INIT ROUTERS
    const userRouter = getUserRouter(db, log, tokenValidator);

    api.use(express.json({ limit: "20mb" }));
    api.use(helmet());

    if (!jestRun()) {
        api.use(morgan("dev", { stream: process.stdout }));
    }

    api.use(cors());

    api.get("/server/:id", async (req, res) => {
        const server = await db.retrieveServer(req.params.id);

        if (server) {
            return res.send(server);
        } else {
            res.sendStatus(404);
        }
    });

    api.get("/channel/:id", async (req, res) => {
        const channel = await db.retrieveChannel(req.params.id);

        if (channel) {
            return res.send(channel);
        } else {
            res.sendStatus(404);
        }
    });

    // user
    api.use("/user", userRouter);

    // device
    api.get("/device/:id", async (req, res) => {
        const device = await db.retrieveDevice(req.params.id);

        if (device) {
            return res.send(device);
        } else {
            res.sendStatus(404);
        }
    });

    // file
    api.get("/file/:id", async (req, res) => {
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

    api.post("/file", multer().single("file"), async (req, res) => {
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
            fileID: uuid.v4(),
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

    // avatar
    api.get("/avatar/:userID", async (req, res) => {
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

    api.post("/avatar/:userID", multer().single("avatar"), async (req, res) => {
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

    api.get("/canary", async (req, res) => {
        res.send({ canary: process.env.CANARY });
    });
};

/**
 * @ignore
 */
const jestRun = () => {
    return process.env.JEST_WORKER_ID !== undefined;
};
