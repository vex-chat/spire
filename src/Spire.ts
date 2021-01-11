import fs from "fs";
import { Server } from "http";

import { XUtils } from "@vex-chat/crypto";
import { XTypes } from "@vex-chat/types";
import { EventEmitter } from "events";
import express from "express";
import expressWs from "express-ws";
import nacl from "tweetnacl";
import * as uuid from "uuid";
import winston from "winston";
import WebSocket from "ws";

import { ClientManager } from "./ClientManager";
import { Database } from "./Database";
import { initApp } from "./server";
import { censorUser } from "./server/utils";
import { createLogger } from "./utils/createLogger";

// expiry of regkeys
export const EXPIRY_TIME = 1000 * 60 * 5;

// 3-19 chars long
const usernameRegex = /^(\w{3,19})$/;

const directories = ["files", "avatars"];
for (const dir of directories) {
    if (!fs.existsSync(dir)) {
        fs.mkdirSync(dir);
    }
}

const TokenScopes = XTypes.HTTP.TokenScopes;

export interface ISpireOptions {
    logLevel?:
        | "error"
        | "warn"
        | "info"
        | "http"
        | "verbose"
        | "debug"
        | "silly";
    apiPort?: number;
    dbType?: "sqlite3" | "mysql" | "sqlite3mem";
}

export class Spire extends EventEmitter {
    private db: Database;
    private clients: ClientManager[] = [];

    private expWs: expressWs.Instance = expressWs(express());
    private api = this.expWs.app;
    private wss: WebSocket.Server = this.expWs.getWss();

    private actionTokens: XTypes.HTTP.IActionToken[] = [];

    private log: winston.Logger;
    private server: Server | null = null;
    private options: ISpireOptions | undefined;

    constructor(options?: ISpireOptions) {
        super();

        this.db = new Database(options);

        this.log = createLogger("spire", options?.logLevel || "error");
        this.init(options?.apiPort || 16777);

        this.options = options;
    }

    public async close(): Promise<void> {
        this.wss.clients.forEach((ws) => {
            ws.terminate();
        });

        this.wss.on("close", () => {
            this.log.info("ws: closed.");
        });

        this.server?.on("close", () => {
            this.log.info("http: closed.");
        });

        this.server?.close();
        this.wss.close();
        await this.db.close();
        return;
    }

    private notify(
        userID: string,
        event: string,
        transmissionID: string,
        data?: any,
        deviceID?: string
    ): void {
        for (const client of this.clients) {
            if (deviceID) {
                if (client.getDevice().deviceID === deviceID) {
                    const msg: XTypes.WS.INotifyMsg = {
                        transmissionID,
                        type: "notify",
                        event,
                        data,
                    };
                    client.send(msg);
                }
            } else {
                if (client.getUser().userID === userID) {
                    const msg: XTypes.WS.INotifyMsg = {
                        transmissionID,
                        type: "notify",
                        event,
                        data,
                    };
                    client.send(msg);
                }
            }
        }
    }

    private createActionToken(
        scope: XTypes.HTTP.TokenScopes
    ): XTypes.HTTP.IActionToken {
        const token: XTypes.HTTP.IActionToken = {
            key: uuid.v4(),
            time: new Date(Date.now()),
            scope,
        };
        this.actionTokens.push(token);
        return token;
    }

    private deleteActionToken(key: XTypes.HTTP.IActionToken) {
        if (this.actionTokens.includes(key)) {
            this.actionTokens.splice(this.actionTokens.indexOf(key), 1);
        }
    }

    private validateToken(
        key: string,
        scope: XTypes.HTTP.TokenScopes
    ): boolean {
        this.log.info("Validating token: " + key);
        for (const rKey of this.actionTokens) {
            if (rKey.key === key) {
                if (rKey.scope !== scope) {
                    continue;
                }

                const age =
                    new Date(Date.now()).getTime() - rKey.time.getTime();
                this.log.info("Regkey found, " + age + " ms old.");
                if (age < EXPIRY_TIME) {
                    this.log.info("Regkey is valid.");
                    this.deleteActionToken(rKey);
                    return true;
                } else {
                    this.log.info("Regkey is expired.");
                }
            }
        }
        this.log.info("Regkey not found.");
        return false;
    }

    private init(apiPort: number): void {
        // initialize the expression app configuration with loose routes/handlers
        initApp(this.api, this.db, this.log, this.validateToken.bind(this));

        // All the app logic strongly coupled to spire class :/
        this.api.ws("/socket", (ws, req) => {
            this.log.info("New client initiated.");
            const client = new ClientManager(
                ws,
                this.db,
                this.notify.bind(this),
                this.options
            );

            client.on("fail", () => {
                this.log.info(
                    "Client connection is down, removing: " + client.toString()
                );
                if (this.clients.includes(client)) {
                    this.clients.splice(this.clients.indexOf(client), 1);
                }
                this.log.info(
                    "Current authorized clients: " + this.clients.length
                );
            });

            client.on("authed", () => {
                this.log.info("New client authorized: " + client.toString());
                this.clients.push(client);
                this.log.info(
                    "Current authorized clients: " + this.clients.length
                );
            });
        });

        this.api.get("/token/:tokenType", async (req, res) => {
            const allowedTokens = ["file", "register", "avatar", "device"];

            const { tokenType } = req.params;
            if (!allowedTokens.includes(tokenType)) {
                res.sendStatus(400);
                return;
            }

            let scope;

            switch (tokenType) {
                case "file":
                    scope = TokenScopes.File;
                    break;
                case "register":
                    scope = TokenScopes.Register;
                    break;
                case "avatar":
                    scope = TokenScopes.Avatar;
                    break;
                case "device":
                    scope = TokenScopes.Device;
                    break;
                default:
                    res.sendStatus(500);
                    return;
            }

            try {
                this.log.info("New token requested of type " + tokenType);
                const token = this.createActionToken(scope);
                this.log.info("New token created: " + token.key);

                setTimeout(() => {
                    this.deleteActionToken(token);
                }, EXPIRY_TIME);

                return res.status(201).send(token);
            } catch (err) {
                this.log.error(err.toString());
                return res.sendStatus(500);
            }
        });

        this.api.post("/register/key", (req, res) => {
            try {
                this.log.info("New regkey requested.");
                const regKey = this.createActionToken(TokenScopes.Register);
                this.log.info("New regkey created: " + regKey.key);

                setTimeout(() => {
                    this.deleteActionToken(regKey);
                }, EXPIRY_TIME);

                return res.status(201).send(regKey);
            } catch (err) {
                this.log.error(err.toString());
                return res.sendStatus(500);
            }
        });

        // 19 char max limit for username
        this.api.post("/register/new", async (req, res) => {
            try {
                const regPayload: XTypes.HTTP.IDevicePayload = req.body;

                if (!usernameRegex.test(regPayload.username)) {
                    res.status(400).send({
                        error:
                            "Username must be between three and nineteen letters, digits, or underscores.",
                    });
                    return;
                }

                const regKey = nacl.sign.open(
                    XUtils.decodeHex(regPayload.signed),
                    XUtils.decodeHex(regPayload.signKey)
                );
                if (
                    regKey &&
                    this.validateToken(
                        uuid.stringify(regKey),
                        TokenScopes.Register
                    )
                ) {
                    const [user, err] = await this.db.createUser(
                        regKey,
                        regPayload
                    );
                    if (err !== null) {
                        switch ((err as any).code) {
                            case "ER_DUP_ENTRY":
                                const usernameConflict = err
                                    .toString()
                                    .includes("users_username_unique");
                                const signKeyConflict = err
                                    .toString()
                                    .includes("users_signkey_unique");

                                this.log.warn(
                                    "User attempted to register duplicate account."
                                );
                                if (usernameConflict) {
                                    res.status(400).send({
                                        error:
                                            "Username is already registered.",
                                    });
                                    return;
                                }
                                if (signKeyConflict) {
                                    res.status(400).send({
                                        error:
                                            "Public key is already registered.",
                                    });
                                    return;
                                }
                                res.status(500).send({
                                    error: "An error occurred registering.",
                                });
                                break;
                            default:
                                this.log.info(
                                    "Unsupported sql error type: " +
                                        (err as any).code
                                );
                                this.log.error(err);
                                res.sendStatus(500);
                                break;
                        }
                    } else {
                        this.log.info("Registration success.");
                        res.send(censorUser(user!));
                    }
                } else {
                    res.status(400).send({
                        error: "Invalid or no token supplied.",
                    });
                }
            } catch (err) {
                this.log.error("error registering user: " + err.toString());
                res.sendStatus(500);
            }
        });

        this.server = this.api.listen(apiPort, () => {
            this.log.info("API started on port " + apiPort.toString());
        });
    }
}
