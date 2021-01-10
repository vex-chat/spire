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
import winston from "winston";

import { Database } from "../Database";
import { getUserRouter } from "./user";
import { getFileRouter } from "./file";

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
    const fileRouter = getFileRouter(db, log);

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

    api.get("/device/:id", async (req, res) => {
        const device = await db.retrieveDevice(req.params.id);

        if (device) {
            return res.send(device);
        } else {
            res.sendStatus(404);
        }
    });

    api.get("/canary", async (req, res) => {
        res.send({ canary: process.env.CANARY });
    });

    api.use("/user", userRouter);

    // file
    api.use("/file", fileRouter);

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
};

/**
 * @ignore
 */
const jestRun = () => {
    return process.env.JEST_WORKER_ID !== undefined;
};
