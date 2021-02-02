import fs from "fs";

import { XTypes } from "@vex-chat/types";
import cookieParser from "cookie-parser";
import cors from "cors";
import express from "express";
import expressWs from "express-ws";

import helmet from "helmet";
import morgan from "morgan";
import parseDuration from "parse-duration";
import winston from "winston";

import { Database } from "../Database";

import { XUtils } from "@vex-chat/crypto";
import atob from "atob";
import FileType from "file-type";
import jwt from "jsonwebtoken";
import msgpack from "msgpack-lite";
import multer from "multer";
import nacl from "tweetnacl";
import { getAvatarRouter } from "./avatar";
import { getFileRouter } from "./file";
import { getInviteRouter } from "./invite";
import { getUserRouter } from "./user";

import * as uuid from "uuid";
import { POWER_LEVELS } from "../ClientManager";
import { JWT_EXPIRY } from "../Spire";
import { censorUser, ICensoredUser } from "./utils";

// expiry of regkeys
export const EXPIRY_TIME = 1000 * 60 * 5;

export const ALLOWED_IMAGE_TYPES = [
    "image/jpeg",
    "image/png",
    "image/gif",
    "image/apng",
    "image/avif",
];

const TokenScopes = XTypes.HTTP.TokenScopes;

interface IInvitePayload {
    serverID: string;
    duration: string;
}

const checkAuth = (req: any, res: any, next: () => void) => {
    if (req.cookies.auth) {
        try {
            const result = jwt.verify(req.cookies.auth, process.env.SPK!);

            // lol glad this is a try/catch block
            (req as any).user = (result as any).user;
            (req as any).exp = (result as any).exp;
        } catch (err) {
            console.warn(err.toString());
        }
    }
    next();
};

const checkDevice = (req: any, res: any, next: () => void) => {
    if (req.cookies.device) {
        try {
            const result = jwt.verify(req.cookies.device, process.env.SPK!);
            // lol glad this is a try/catch block
            (req as any).device = (result as any).device;
        } catch (err) {
            console.warn(err.toString());
        }
    }
    next();
};

export const protect = (req: any, res: any, next: () => void) => {
    if (!req.user) {
        res.sendStatus(401);
        throw new Error("not authenticated!");
    }

    next();
};

export const msgpackParser = (req: any, res: any, next: () => void) => {
    if (req.is("application/msgpack")) {
        try {
            req.body = msgpack.decode(req.body);
        } catch (err) {
            res.sendStatus(400);
            return;
        }
    }
    next();
};

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
    api.use(
        express.raw({
            type: "application/msgpack",
            limit: "20mb",
        })
    );
    api.use(helmet());
    api.use(cookieParser());
    api.use(msgpackParser);
    api.use(checkAuth);
    api.use(checkDevice);

    if (!jestRun()) {
        api.use(morgan("dev", { stream: process.stdout }));
    }

    api.use(cors({ credentials: true }));

    api.get("/server/:id", protect, async (req, res) => {
        const server = await db.retrieveServer(req.params.id);

        if (server) {
            return res.send(msgpack.encode(server));
        } else {
            res.sendStatus(404);
        }
    });

    api.post("/server/:name", protect, async (req, res) => {
        const userDetails: ICensoredUser = (req as any).user;
        const serverName = atob(req.params.name);

        const server = await db.createServer(serverName, userDetails.userID);
        res.send(msgpack.encode(server));
    });

    api.post("/server/:serverID/invites", protect, async (req, res) => {
        const userDetails: ICensoredUser = (req as any).user;

        const payload: IInvitePayload = req.body;
        const serverEntry = await db.retrieveServer(req.params.serverID);

        if (!serverEntry) {
            res.sendStatus(404);
            return;
        }

        const permissions = await db.retrievePermissions(
            userDetails.userID,
            "server"
        );

        let hasPermission = false;
        for (const permission of permissions) {
            if (
                permission.resourceID === req.params.serverID &&
                permission.powerLevel > POWER_LEVELS.INVITE
            ) {
                hasPermission = true;
            }
        }

        if (!hasPermission) {
            log.warn("No permission!");
            res.sendStatus(401);
            return;
        }

        const duration = parseDuration(payload.duration, "ms");

        if (!duration) {
            res.sendStatus(400);
            return;
        }

        const expires = new Date(Date.now() + duration);

        const invite = await db.createInvite(
            uuid.v4(),
            serverEntry.serverID,
            userDetails.userID,
            expires.toString()
        );
        res.send(msgpack.encode(invite));
    });

    api.get("/server/:serverID/invites", protect, async (req, res) => {
        const userDetails: ICensoredUser = (req as any).user;

        const permissions = await db.retrievePermissions(
            userDetails.userID,
            "server"
        );

        let hasPermission = false;
        for (const permission of permissions) {
            if (
                permission.resourceID === req.params.serverID &&
                permission.powerLevel > POWER_LEVELS.INVITE
            ) {
                hasPermission = true;
            }
        }
        if (!hasPermission) {
            res.sendStatus(401);
            return;
        }

        const inviteList = await db.retrieveServerInvites(req.params.serverID);
        res.send(msgpack.encode(inviteList));
    });

    api.delete("/server/:id", protect, async (req, res) => {
        const userDetails = (req as any).user;
        const serverID = req.params.id;
        const permissions = await db.retrievePermissions(
            userDetails.userID,
            "server"
        );
        for (const permission of permissions) {
            if (
                permission.resourceID === serverID &&
                permission.powerLevel > POWER_LEVELS.DELETE
            ) {
                // msg.data is the serverID
                await db.deleteServer(serverID);
                res.sendStatus(200);
                return;
            }
        }
        res.sendStatus(401);
    });

    api.post("/server/:id/channels", protect, async (req, res) => {
        const userDetails: ICensoredUser = (req as any).user;
        const serverID = req.params.id;
        // resourceID is serverID
        const { name } = req.body;
        const permissions = await db.retrievePermissions(
            userDetails.userID,
            "server"
        );
        for (const permission of permissions) {
            if (
                permission.resourceID === serverID &&
                permission.powerLevel > POWER_LEVELS.CREATE
            ) {
                const channel = await db.createChannel(name, serverID);
                res.send(msgpack.encode(channel));

                const affectedUsers = await db.retrieveAffectedUsers(serverID);
                // tell everyone about server change
                for (const user of affectedUsers) {
                    notify(user.userID, "serverChange", uuid.v4(), serverID);
                }
                return;
            }
        }
        res.sendStatus(401);
    });

    api.get("/server/:id/channels", protect, async (req, res) => {
        const serverID = req.params.id;
        const userDetails = (req as any).user;
        const permissions = await db.retrievePermissions(
            userDetails.userID,
            "server"
        );
        for (const permission of permissions) {
            if (serverID === permission.resourceID) {
                const channels = await db.retrieveChannels(
                    permission.resourceID
                );
                res.send(msgpack.encode(channels));
                return;
            }
        }
        res.sendStatus(401);
    });

    api.get("/server/:serverID/emoji", protect, async (req, res) => {
        const rows = await db.retrieveEmojiList(req.params.serverID);
        res.send(msgpack.encode(rows));
    });

    api.get("/server/:serverID/permissions", protect, async (req, res) => {
        const userDetails: ICensoredUser = (req as any).user;
        const serverID = req.params.serverID;
        try {
            const permissions = await db.retrievePermissionsByResourceID(
                serverID
            );
            if (permissions) {
                let found = false;
                for (const perm of permissions) {
                    if (perm.userID === userDetails.userID) {
                        res.send(msgpack.encode(permissions));
                        found = true;
                        break;
                    }
                }
                if (!found) {
                    res.sendStatus(401);
                    return;
                }
            } else {
                res.sendStatus(404);
            }
        } catch (err) {
            res.status(500).send(err.toString());
        }
    });

    api.delete("/channel/:id", protect, async (req, res) => {
        const channelID = req.params.id;
        const userDetails: ICensoredUser = (req as any).user;

        const channel = await db.retrieveChannel(channelID);

        if (!channel) {
            res.sendStatus(401);
            return;
        }

        const permissions = await db.retrievePermissions(
            userDetails.userID,
            "server"
        );
        let found = false;
        for (const permission of permissions) {
            if (
                permission.resourceID === channel.serverID &&
                permission.powerLevel > 50
            ) {
                found = true;
                // msg.data is the channelID
                await db.deleteChannel(channelID);

                res.sendStatus(200);

                const affectedUsers = await db.retrieveAffectedUsers(
                    channel.serverID
                );
                // tell everyone about server change
                for (const user of affectedUsers) {
                    notify(
                        user.userID,
                        "serverChange",
                        uuid.v4(),
                        channel.serverID
                    );
                }
                return;
            }
        }
        res.sendStatus(401);
    });

    api.get("/channel/:id", protect, async (req, res) => {
        const channel = await db.retrieveChannel(req.params.id);

        if (channel) {
            return res.send(msgpack.encode(channel));
        } else {
            res.sendStatus(404);
        }
    });

    api.delete("/permission/:permissionID", protect, async (req, res) => {
        const permissionID = req.params.permissionID;
        const userDetails: ICensoredUser = (req as any).user;
        try {
            // msg.data is permID
            const permToDelete = await db.retrievePermission(permissionID);
            if (!permToDelete) {
                res.sendStatus(404);
                return;
            }

            const permissions = await db.retrievePermissions(
                userDetails.userID,
                permToDelete.resourceType
            );

            for (const perm of permissions) {
                // msg.data is resourceID
                if (
                    perm.resourceID === permToDelete.resourceID &&
                    (perm.userID === userDetails.userID ||
                        (perm.powerLevel > POWER_LEVELS.DELETE &&
                            perm.powerLevel > permToDelete.powerLevel))
                ) {
                    db.deletePermission(permToDelete.permissionID);
                    res.sendStatus(200);
                    return;
                }
            }
            res.sendStatus(401);
            return;
        } catch (err) {
            res.status(500).send(err.toString());
        }
    });

    api.post("/userList/:channelID", async (req, res) => {
        const userDetails: ICensoredUser = (req as any).user;
        const channelID: string = req.params.channelID;

        try {
            const channel = await db.retrieveChannel(channelID);
            if (!channel) {
                res.sendStatus(404);
                return;
            }
            const permissions = await db.retrievePermissions(
                userDetails.userID,
                "server"
            );
            for (const permission of permissions) {
                if (permission.resourceID === channel.serverID) {
                    // we've got the permission, it's ok to give them the userlist
                    const groupMembers = await db.retrieveGroupMembers(
                        channelID
                    );
                    res.send(
                        msgpack.encode(
                            groupMembers.map((user) => censorUser(user))
                        )
                    );
                }
            }
        } catch (err) {
            log.error(err.toString());
            res.status(500).send(err.toString());
        }
    });

    api.post("/deviceList", protect, async (req, res) => {
        const userIDs: string[] = req.body;
        const devices = await db.retrieveUserDeviceList(userIDs);
        res.send(msgpack.encode(devices));
    });

    api.get("/device/:id", protect, async (req, res) => {
        const device = await db.retrieveDevice(req.params.id);

        if (device) {
            return res.send(msgpack.encode(device));
        } else {
            res.sendStatus(404);
        }
    });

    api.post("/device/:id/keyBundle", protect, async (req, res) => {
        try {
            const keyBundle = await db.getKeyBundle(req.params.id);
            if (keyBundle) {
                res.send(msgpack.encode(keyBundle));
            } else {
                res.sendStatus(404);
            }
        } catch (err) {
            res.sendStatus(500);
        }
    });

    api.post("/device/:id/connect", protect, async (req, res) => {
        const { signed }: { signed: Uint8Array } = req.body;
        const device = await db.retrieveDevice(req.params.id);
        if (!device) {
            res.sendStatus(404);
            return;
        }

        const regKey = nacl.sign.open(signed, XUtils.decodeHex(device.signKey));
        if (
            regKey &&
            tokenValidator(uuid.stringify(regKey), TokenScopes.Connect)
        ) {
            const token = jwt.sign({ device }, process.env.SPK!, {
                expiresIn: JWT_EXPIRY,
            });
            jwt.verify(token, process.env.SPK!);

            res.cookie("device", token, { path: "/" });
            res.sendStatus(200);
        } else {
            res.sendStatus(401);
        }
    });

    api.get("/device/:id/otk/count", protect, async (req, res) => {
        const deviceDetails: XTypes.SQL.IDevice | undefined = (req as any)
            .device;
        if (!deviceDetails) {
            res.sendStatus(401);
            return;
        }

        try {
            const count = await db.getOTKCount(deviceDetails.deviceID);
            res.send(msgpack.encode({ count }));
            return;
        } catch (err) {
            res.status(500).send(err.toString());
        }
    });

    api.post("/device/:id/otk", protect, async (req, res) => {
        const submittedOTKs: XTypes.WS.IPreKeys[] = req.body;
        const userDetails = (req as any).user;

        const deviceID = req.params.id;

        const [otk] = submittedOTKs;

        const device = await db.retrieveDevice(deviceID);
        if (!device) {
            res.sendStatus(404);
            return;
        }

        const message = nacl.sign.open(
            otk.signature,
            XUtils.decodeHex(device.signKey)
        );

        if (!message) {
            res.sendStatus(401);
            return;
        }

        try {
            await db.saveOTK(userDetails.userID, deviceID, submittedOTKs);
            res.sendStatus(200);
        } catch (err) {
            res.status(500).send(err.toString());
        }
    });

    interface IEmojiPayload {
        signed: string;
        name: string;
        file?: string;
    }

    api.get("/emoji/:emojiID/details", protect, async (req, res) => {
        const emoji = await db.retrieveEmoji(req.params.emojiID);
        res.send(msgpack.encode(emoji));
    });

    api.get("/emoji/:emojiID", protect, async (req, res) => {
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

    api.post("/emoji/:serverID/json", protect, async (req, res) => {
        const payload: IEmojiPayload = req.body;

        const userDetails: ICensoredUser = (req as any).user;
        const device: XTypes.SQL.IDevice | undefined = (req as any).device;

        if (!device) {
            res.sendStatus(401);
            return;
        }

        const buf = Buffer.from(XUtils.decodeBase64(payload.file!));
        const serverEntry = await db.retrieveServer(req.params.serverID);

        const permissionList = await db.retrievePermissionsByResourceID(
            req.params.serverID
        );
        let hasPermission = false;
        for (const permission of permissionList) {
            if (
                permission.userID === userDetails.userID &&
                permission.powerLevel > POWER_LEVELS.EMOJI
            ) {
                hasPermission = true;
                break;
            }
        }

        if (!hasPermission) {
            res.sendStatus(401);
            return;
        }
        if (!serverEntry) {
            res.sendStatus(404);
            return;
        }
        if (!payload.name) {
            res.sendStatus(400);
        }
        if (Buffer.byteLength(buf) > 256000) {
            console.warn("File to big.");
            res.sendStatus(413);
        }

        const mimeType = await FileType.fromBuffer(buf);
        if (!ALLOWED_IMAGE_TYPES.includes(mimeType?.mime || "no/type")) {
            res.status(400).send({
                error:
                    "Unsupported file type. Expected jpeg, png, gif, apng, or avif but received " +
                    mimeType?.ext,
            });
            return;
        }

        const emoji: XTypes.SQL.IEmoji = {
            emojiID: uuid.v4(),
            owner: req.params.serverID,
            name: payload.name,
        };

        await db.createEmoji(emoji);

        try {
            // write the file to disk
            fs.writeFile("emoji/" + emoji.emojiID, buf, () => {
                log.info("Wrote new emoji " + emoji.emojiID);
            });
            res.send(msgpack.encode(emoji));
        } catch (err) {
            log.warn(err);
            res.sendStatus(500);
        }
    });

    api.post(
        "/emoji/:serverID",
        protect,
        multer().single("emoji"),
        async (req, res) => {
            const payload: IEmojiPayload = req.body;
            const serverEntry = await db.retrieveServer(req.params.serverID);
            const userDetails: ICensoredUser = (req as any).user;
            const deviceDetails: XTypes.SQL.IDevice | undefined = (req as any)
                .device;
            if (!deviceDetails) {
                res.sendStatus(401);
                return;
            }

            const permissionList = await db.retrievePermissionsByResourceID(
                req.params.serverID
            );
            let hasPermission = false;
            for (const permission of permissionList) {
                if (
                    permission.userID === userDetails.userID &&
                    permission.powerLevel > POWER_LEVELS.EMOJI
                ) {
                    hasPermission = true;
                    break;
                }
            }
            if (!hasPermission) {
                res.sendStatus(401);
                return;
            }

            if (!serverEntry) {
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

            if (Buffer.byteLength(req.file.buffer) > 256000) {
                console.warn("File to big.");
                res.sendStatus(413);
            }

            const mimeType = await FileType.fromBuffer(req.file.buffer);
            if (!ALLOWED_IMAGE_TYPES.includes(mimeType?.mime || "no/type")) {
                res.status(400).send({
                    error:
                        "Unsupported file type. Expected jpeg, png, gif, apng, or avif but received " +
                        mimeType?.ext,
                });
                return;
            }

            const emoji: XTypes.SQL.IEmoji = {
                emojiID: uuid.v4(),
                owner: req.params.serverID,
                name: payload.name,
            };

            await db.createEmoji(emoji);

            try {
                // write the file to disk
                fs.writeFile("emoji/" + emoji.emojiID, req.file.buffer, () => {
                    log.info("Wrote new emoji " + emoji.emojiID);
                });
                res.send(msgpack.encode(emoji));
            } catch (err) {
                log.warn(err);
                res.sendStatus(500);
            }
        }
    );

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
