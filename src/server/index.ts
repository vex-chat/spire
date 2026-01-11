import fs from "fs";
import * as XTypes from "@vex-chat/types";
import { XUtils } from "@vex-chat/crypto";
import cookieParser from "cookie-parser";
import cors from "cors";
import express, { Request, Response, NextFunction, Application } from "express";
import helmet from "helmet";
import morgan from "morgan";
import parseDuration from "parse-duration";
import winston from "winston";
import { Database } from "../Database";
import atob from "atob";
import jwt from "jsonwebtoken";
import { getAvatarRouter } from "./avatar";
import { getFileRouter } from "./file";
import { getInviteRouter } from "./invite";
import { getUserRouter } from "./user";
import * as uuid from "uuid";
import { POWER_LEVELS } from "../ClientManager";
import { censorUser, ICensoredUser } from "./utils";
import { Packr } from "msgpackr";
import nacl from "tweetnacl";
import { JWT_EXPIRY } from "../Spire";

// --- GLOBAL TYPE AUGMENTATION ---
declare global {
  namespace Express {
    interface Request {
      user?: ICensoredUser;
      device?: XTypes.IDevice;
      exp?: number;
    }
  }
}

export const EXPIRY_TIME = 1000 * 60 * 5;

export const ALLOWED_IMAGE_TYPES = [
  "image/jpeg",
  "image/png",
  "image/gif",
  "image/apng",
  "image/avif",
];

const TokenScopes = XTypes.TokenScopes;

function getErrorMessage(error: unknown): string {
  if (error instanceof Error) return error.message;
  return String(error);
}

interface IInvitePayload {
  serverID: string;
  duration: string;
}

const checkAuth = (req: Request, res: Response, next: NextFunction) => {
  if (req.cookies.auth) {
    try {
      const secret = process.env.SPK;
      if (!secret) throw new Error("SPK not set");

      const result = jwt.verify(req.cookies.auth, secret) as {
        user: ICensoredUser;
        exp: number;
      };
      req.user = result.user;
      req.exp = result.exp;
    } catch (err) {
      console.warn("Auth check failed:", getErrorMessage(err));
    }
  }
  next();
};

const checkDevice = (req: Request, res: Response, next: NextFunction) => {
  if (req.cookies.device) {
    try {
      const secret = process.env.SPK;
      if (!secret) throw new Error("SPK not set");

      const result = jwt.verify(req.cookies.device, secret) as {
        device: XTypes.IDevice;
      };
      req.device = result.device;
    } catch (err) {
      console.warn("Device check failed:", getErrorMessage(err));
    }
  }
  next();
};

export const protect = (req: Request, res: Response, next: NextFunction) => {
  if (!req.user) {
    res.sendStatus(401);
    return;
  }
  next();
};

const packer = new Packr({ useRecords: false, moreTypes: true });

export const msgpackParser = (
  req: Request,
  res: Response,
  next: NextFunction,
) => {
  if (req.is("application/msgpack")) {
    try {
      if (req.body && Buffer.isBuffer(req.body)) {
        req.body = packer.unpack(req.body);
      }
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
  api: Application, // CHANGED: Forced to standard Express Application to resolve overload errors
  db: Database,
  log: winston.Logger,
  tokenValidator: (key: string, scope: XTypes.TokenScopes) => boolean,
  signKeys: nacl.SignKeyPair,
  notify: (
    userID: string,
    event: string,
    transmissionID: string,
    data?: any,
    deviceID?: string,
  ) => void,
) => {
  const userRouter = getUserRouter(db, log, tokenValidator);
  const fileRouter = getFileRouter(db, log);
  const avatarRouter = getAvatarRouter(db, log);
  const inviteRouter = getInviteRouter(db, log, tokenValidator, notify);

  api.use(express.json({ limit: "20mb" }));
  api.use(
    express.raw({
      type: "application/msgpack",
      limit: "20mb",
    }),
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
    try {
      const server = await db.retrieveServer(req.params.id);
      if (server) {
        res.send(Buffer.from(packer.pack(server)));
      } else {
        res.sendStatus(404);
      }
    } catch (err) {
      log.error(getErrorMessage(err));
      res.sendStatus(500);
    }
  });

  api.post("/server/:name", protect, async (req, res) => {
    try {
      const userDetails = req.user!;
      const serverName = atob(req.params.name);

      const server = await db.createServer(serverName, userDetails.userID);
      res.send(Buffer.from(packer.pack(server)));
    } catch (err) {
      log.error(getErrorMessage(err));
      res.status(500).send(getErrorMessage(err));
    }
  });

  api.post("/server/:serverID/invites", protect, async (req, res) => {
    try {
      const userDetails = req.user!;
      const payload: IInvitePayload = req.body;
      const serverEntry = await db.retrieveServer(req.params.serverID);

      if (!serverEntry) {
        res.sendStatus(404);
        return;
      }

      const permissions = await db.retrievePermissions(
        userDetails.userID,
        "server",
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
        expires.toString(),
      );
      res.send(Buffer.from(packer.pack(invite)));
    } catch (err) {
      log.error(getErrorMessage(err));
      res.status(500).send(getErrorMessage(err));
    }
  });

  api.get("/server/:serverID/invites", protect, async (req, res) => {
    try {
      const userDetails = req.user!;
      const permissions = await db.retrievePermissions(
        userDetails.userID,
        "server",
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
      res.send(Buffer.from(packer.pack(inviteList)));
    } catch (err) {
      log.error(getErrorMessage(err));
      res.status(500).send(getErrorMessage(err));
    }
  });

  api.delete("/server/:id", protect, async (req, res) => {
    try {
      const userDetails = req.user!;
      const serverID = req.params.id;
      const permissions = await db.retrievePermissions(
        userDetails.userID,
        "server",
      );
      for (const permission of permissions) {
        if (
          permission.resourceID === serverID &&
          permission.powerLevel > POWER_LEVELS.DELETE
        ) {
          await db.deleteServer(serverID);
          res.sendStatus(200);
          return;
        }
      }
      res.sendStatus(401);
    } catch (err) {
      log.error(getErrorMessage(err));
      res.status(500).send(getErrorMessage(err));
    }
  });

  api.post("/server/:id/channels", protect, async (req, res) => {
    try {
      const userDetails = req.user!;
      const serverID = req.params.id;
      const { name } = req.body;
      const permissions = await db.retrievePermissions(
        userDetails.userID,
        "server",
      );
      for (const permission of permissions) {
        if (
          permission.resourceID === serverID &&
          permission.powerLevel > POWER_LEVELS.CREATE
        ) {
          const channel = await db.createChannel(name, serverID);
          res.send(Buffer.from(packer.pack(channel)));

          const affectedUsers = await db.retrieveAffectedUsers(serverID);
          for (const user of affectedUsers) {
            notify(user.userID, "serverChange", uuid.v4(), serverID);
          }
          return;
        }
      }
      res.sendStatus(401);
    } catch (err) {
      log.error(getErrorMessage(err));
      res.status(500).send(getErrorMessage(err));
    }
  });

  api.get("/server/:id/channels", protect, async (req, res) => {
    try {
      const serverID = req.params.id;
      const userDetails = req.user!;
      const permissions = await db.retrievePermissions(
        userDetails.userID,
        "server",
      );
      for (const permission of permissions) {
        if (serverID === permission.resourceID) {
          const channels = await db.retrieveChannels(permission.resourceID);
          res.send(Buffer.from(packer.pack(channels)));
          return;
        }
      }
      res.sendStatus(401);
    } catch (err) {
      log.error(getErrorMessage(err));
      res.status(500).send(getErrorMessage(err));
    }
  });

  api.get("/server/:serverID/emoji", protect, async (req, res) => {
    try {
      const rows = await db.retrieveEmojiList(req.params.serverID);
      res.send(Buffer.from(packer.pack(rows)));
    } catch (err) {
      log.error(getErrorMessage(err));
      res.status(500).send(getErrorMessage(err));
    }
  });

  api.get("/server/:serverID/permissions", protect, async (req, res) => {
    const userDetails = req.user!;
    const serverID = req.params.serverID;
    try {
      const permissions = await db.retrievePermissionsByResourceID(serverID);
      if (permissions) {
        let found = false;
        for (const perm of permissions) {
          if (perm.userID === userDetails.userID) {
            res.send(Buffer.from(packer.pack(permissions)));
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
      res.status(500).send(getErrorMessage(err));
    }
  });

  api.delete("/channel/:id", protect, async (req, res) => {
    const channelID = req.params.id;
    const userDetails = req.user!;

    try {
      const channel = await db.retrieveChannel(channelID);

      if (!channel) {
        res.sendStatus(401);
        return;
      }

      const permissions = await db.retrievePermissions(
        userDetails.userID,
        "server",
      );

      for (const permission of permissions) {
        if (
          permission.resourceID === channel.serverID &&
          permission.powerLevel > 50
        ) {
          await db.deleteChannel(channelID);

          res.sendStatus(200);

          const affectedUsers = await db.retrieveAffectedUsers(
            channel.serverID,
          );
          for (const user of affectedUsers) {
            notify(user.userID, "serverChange", uuid.v4(), channel.serverID);
          }
          return;
        }
      }
      res.sendStatus(401);
    } catch (err) {
      log.error(getErrorMessage(err));
      res.status(500).send(getErrorMessage(err));
    }
  });

  api.get("/channel/:id", protect, async (req, res) => {
    try {
      const channel = await db.retrieveChannel(req.params.id);
      if (channel) {
        return res.send(Buffer.from(packer.pack(channel)));
      } else {
        res.sendStatus(404);
      }
    } catch (err) {
      log.error(getErrorMessage(err));
      res.status(500).send(getErrorMessage(err));
    }
  });

  api.delete("/permission/:permissionID", protect, async (req, res) => {
    const permissionID = req.params.permissionID;
    const userDetails = req.user!;
    try {
      const permToDelete = await db.retrievePermission(permissionID);
      if (!permToDelete) {
        res.sendStatus(404);
        return;
      }

      const permissions = await db.retrievePermissions(
        userDetails.userID,
        permToDelete.resourceType,
      );

      for (const perm of permissions) {
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
      res.status(500).send(getErrorMessage(err));
    }
  });

  api.post("/userList/:channelID", async (req, res) => {
    const userDetails = req.user!;
    const channelID: string = req.params.channelID;

    try {
      const channel = await db.retrieveChannel(channelID);
      if (!channel) {
        res.sendStatus(404);
        return;
      }
      const permissions = await db.retrievePermissions(
        userDetails.userID,
        "server",
      );
      for (const permission of permissions) {
        if (permission.resourceID === channel.serverID) {
          const groupMembers = await db.retrieveGroupMembers(channelID);
          res.send(
            Buffer.from(
              packer.pack(groupMembers.map((user) => censorUser(user))),
            ),
          );
        }
      }
    } catch (err) {
      log.error(getErrorMessage(err));
      res.status(500).send(getErrorMessage(err));
    }
  });

  api.post("/deviceList", protect, async (req, res) => {
    try {
      const userIDs: string[] = req.body;
      const devices = await db.retrieveUserDeviceList(userIDs);
      res.send(Buffer.from(packer.pack(devices)));
    } catch (err) {
      log.error(getErrorMessage(err));
      res.status(500).send(getErrorMessage(err));
    }
  });

  api.get("/device/:id", protect, async (req, res) => {
    try {
      const device = await db.retrieveDevice(req.params.id);
      if (device) {
        return res.send(Buffer.from(packer.pack(device)));
      } else {
        res.sendStatus(404);
      }
    } catch (err) {
      log.error(getErrorMessage(err));
      res.status(500).send(getErrorMessage(err));
    }
  });

  api.post("/device/:id/keyBundle", protect, async (req, res) => {
    try {
      const keyBundle = await db.getKeyBundle(req.params.id);
      if (keyBundle) {
        res.send(Buffer.from(packer.pack(keyBundle)));
      } else {
        res.sendStatus(404);
      }
    } catch (err) {
      res.sendStatus(500);
    }
  });

  api.post("/device/:id/mail", protect, async (req, res) => {
    const deviceDetails = req.device;
    if (!deviceDetails) {
      res.sendStatus(401);
      return;
    }
    try {
      const inbox = await db.retrieveMail(deviceDetails.deviceID);
      res.send(Buffer.from(packer.pack(inbox)));
    } catch (err) {
      res.status(500).send(getErrorMessage(err));
    }
  });

  api.post("/device/:id/connect", protect, async (req, res) => {
    try {
      const { signed }: { signed: Uint8Array } = req.body;
      const device = await db.retrieveDevice(req.params.id);
      if (!device) {
        res.sendStatus(404);
        return;
      }

      const regKey = nacl.sign.open(signed, XUtils.decodeHex(device.signKey));
      if (
        regKey &&
        tokenValidator(uuid.stringify(regKey), XTypes.TokenScopes.Connect)
      ) {
        const signOpts: jwt.SignOptions = {
          expiresIn: JWT_EXPIRY as jwt.SignOptions["expiresIn"],
        };
        const token = jwt.sign({ device }, process.env.SPK!, signOpts);
        jwt.verify(token, process.env.SPK!);

        res.cookie("device", token, { path: "/" });
        res.sendStatus(200);
      } else {
        res.sendStatus(401);
      }
    } catch (err) {
      log.error(getErrorMessage(err));
      res.status(500).send(getErrorMessage(err));
    }
  });

  api.get("/device/:id/otk/count", protect, async (req, res) => {
    const deviceDetails = req.device;
    if (!deviceDetails) {
      res.sendStatus(401);
      return;
    }

    try {
      const count = await db.getOTKCount(deviceDetails.deviceID);
      res.send(Buffer.from(packer.pack({ count })));
      return;
    } catch (err) {
      res.status(500).send(getErrorMessage(err));
    }
  });

  api.post("/device/:id/otk", protect, async (req, res) => {
    try {
      const submittedOTKs: XTypes.IPreKeysWS[] = req.body;
      if (submittedOTKs.length === 0) {
        res.sendStatus(200);
        return;
      }

      const userDetails = req.user!;
      const deviceID = req.params.id;
      const [otk] = submittedOTKs;

      const device = await db.retrieveDevice(deviceID);
      if (!device) {
        res.sendStatus(404);
        return;
      }

      const message = nacl.sign.open(
        otk.signature,
        XUtils.decodeHex(device.signKey),
      );

      if (!message) {
        res.sendStatus(401);
        return;
      }

      await db.saveOTK(userDetails.userID, deviceID, submittedOTKs);
      res.sendStatus(200);
    } catch (err) {
      res.status(500).send(getErrorMessage(err));
    }
  });

  api.use("/user", userRouter);
  api.use("/file", fileRouter);
  api.use("/avatar", avatarRouter);
  api.use("/invite", inviteRouter);
};

const jestRun = () => {
  return process.env.JEST_WORKER_ID !== undefined;
};
