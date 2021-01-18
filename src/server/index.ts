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

import jwt from "jsonwebtoken";
import { getAvatarRouter } from "./avatar";
import { getFileRouter } from "./file";
import { getInviteRouter } from "./invite";
import { getUserRouter } from "./user";
import { ICensoredUser } from "./utils";

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
