import fs from "fs";

import { XTypes } from "@vex-chat/types";
import cookieParser from "cookie-parser";
import cors from "cors";
import express from "express";
import expressWs from "express-ws";

import helmet from "helmet";
import morgan from "morgan";
import winston from "winston";

import { Database } from "../Database";

import { XUtils } from "@vex-chat/crypto";
import FileType from "file-type";
import jwt from "jsonwebtoken";
import multer from "multer";
import nacl from "tweetnacl";
import { getAvatarRouter } from "./avatar";
import { getFileRouter } from "./file";
import { getInviteRouter } from "./invite";
import { getUserRouter } from "./user";

import * as uuid from "uuid";

// expiry of regkeys
export const EXPIRY_TIME = 1000 * 60 * 5;

const checkJwt = (req: any, res: any, next: () => void) => {
    if (req.cookies.auth) {
        try {
            const result = jwt.verify(req.cookies.auth, process.env.SPK!);
            // lol glad this is a try/catch block
            (req as any).user = (result as any).user;
        } catch (err) {
            console.warn(err.toString());
        }
    }
    next();
};

export const protect = (req: any, res: any, next: () => void) => {
    if (!req.user) {
        res.sendStatus(401);
        return;
    }
    next();
};

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
    tokenValidator: (key: string, scope: XTypes.HTTP.TokenScopes) => boolean,
    signKeys: nacl.SignKeyPair,
    notify: (
        userID: string,
        event: string,
        transmissionID: string,
        data?: any,
        deviceID?: string
    ) => void
) => {
    // INIT ROUTERS
    const userRouter = getUserRouter(db, log, tokenValidator);
    const fileRouter = getFileRouter(db, log);
    const avatarRouter = getAvatarRouter(db, log);
    const inviteRouter = getInviteRouter(db, log, tokenValidator, notify);

    // MIDDLEWARE
    api.use(express.json({ limit: "20mb" }));
    api.use(helmet());
    api.use(cookieParser());
    api.use(checkJwt);

    if (!jestRun()) {
        api.use(morgan("dev", { stream: process.stdout }));
    }

    api.use(cors({ credentials: true }));

    // SIMPLE RESOURCES
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

    api.post("/deviceList", async (req, res) => {
        const userIDs: string[] = req.body;
        const devices = await db.retrieveUserDeviceList(userIDs);
        res.send(devices);
    });

    api.get("/device/:id", async (req, res) => {
        const device = await db.retrieveDevice(req.params.id);

        if (device) {
            return res.send(device);
        } else {
            res.sendStatus(404);
        }
    });

    interface IEmojiPayload {
        signed: string;
        name: string;
        file?: string;
    }

    api.get("/emoji/:emojiID/details", async (req, res) => {
        const emoji = await db.retrieveEmoji(req.params.emojiID);
        res.send(emoji);
    });

    api.get("/emoji/:emojiID", async (req, res) => {
        const stream = fs.createReadStream("./emoji/" + req.params.emojiID);
        stream.on("error", (err) => {
            // log.error(err.toString());
            res.sendStatus(404);
        });

        const typeDetails = await FileType.fromStream(stream);
        if (typeDetails) {
            res.set("Content-type", typeDetails.mime);
        }

        res.set("Cache-control", "public, max-age=31536000");
        const stream2 = fs.createReadStream("./emoji/" + req.params.emojiID);
        stream2.on("error", (err) => {
            log.error(err.toString());
            res.sendStatus(500);
        });
        stream2.pipe(res);
    });

    api.post("/emoji/:userID", multer().single("emoji"), async (req, res) => {
        const payload: IEmojiPayload = req.body;
        const userEntry = await db.retrieveUser(req.params.userID);

        if (!userEntry) {
            res.sendStatus(404);
            return;
        }

        if (!payload.name) {
            res.sendStatus(400);
        }

        if (!req.file) {
            console.warn("MISSING FILE");
            res.sendStatus(400);
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
                    "Unsupported file type. Expected jpeg, png, gif, apng, or avif but received " +
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

        const emoji: XTypes.SQL.IEmoji = {
            emojiID: uuid.v4(),
            owner: userEntry.userID,
            name: payload.name,
        };

        await db.createEmoji(emoji);

        try {
            // write the file to disk
            fs.writeFile("emoji/" + emoji.emojiID, req.file.buffer, () => {
                log.info("Wrote new emoji " + emoji.emojiID);
            });
            res.send(emoji);
        } catch (err) {
            log.warn(err);
            res.sendStatus(500);
        }
    });

    // COMPLEX RESOURCES
    api.use("/user", userRouter);

    api.use("/file", fileRouter);

    api.use("/avatar", avatarRouter);

    api.use("/invite", inviteRouter);
};

/**
 * @ignore
 */
const jestRun = () => {
    return process.env.JEST_WORKER_ID !== undefined;
};
