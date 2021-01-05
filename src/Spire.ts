import { XUtils } from "@vex-chat/crypto";
import { XTypes } from "@vex-chat/types";
import cors from "cors";
import { EventEmitter } from "events";
import express from "express";
import expressWs from "express-ws";
import fs from "fs";
import helmet from "helmet";
import { Server } from "http";
import knex from "knex";
import morgan from "morgan";
import multer from "multer";
import nacl from "tweetnacl";
import * as uuid from "uuid";
import winston from "winston";
import WebSocket from "ws";
import { ClientManager } from "./ClientManager";
import { Database } from "./Database";
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

        // Move this logic form Database class into Spire until test coverage increases
        switch (options?.dbType || "mysql") {
            case "sqlite3":
                const sql3 = knex({
                    client: "sqlite3",
                    connection: {
                        filename: "spire.sqlite",
                    },
                    useNullAsDefault: true,
                });

                this.db = new Database(sql3, options);
                break;
            case "sqlite3mem":
                const sql3mem = knex({
                    client: "sqlite3",
                    connection: {
                        filename: ":memory:",
                    },
                    useNullAsDefault: true,
                });
                this.db = new Database(sql3mem, options);
                break;
            case "mysql":
            default:
                const mysql = knex({
                    client: "mysql",
                    connection: {
                        host: process.env.SQL_HOST,
                        user: process.env.SQL_USER,
                        password: process.env.SQL_PASSWORD,
                        database: process.env.SQL_DB_NAME,
                    },
                });
                this.db = new Database(mysql, options);
                break;
        }

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
        data?: any
    ): void {
        for (const client of this.clients) {
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
        this.api.use(express.json({ limit: "20mb" }));
        this.api.use(helmet());

        if (!jestRun()) {
            this.api.use(morgan("dev", { stream: process.stdout }));
        }

        this.api.use(cors());

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

        this.api.get("/server/:id", async (req, res) => {
            const server = await this.db.retrieveServer(req.params.id);

            if (server) {
                return res.send(server);
            } else {
                res.sendStatus(404);
            }
        });

        this.api.get("/channel/:id", async (req, res) => {
            const channel = await this.db.retrieveChannel(req.params.id);

            if (channel) {
                return res.send(channel);
            } else {
                res.sendStatus(404);
            }
        });

        this.api.get("/user/:id", async (req, res) => {
            const user = await this.db.retrieveUser(req.params.id);

            if (user) {
                return res.send(user);
            } else {
                res.sendStatus(404);
            }
        });

        this.api.get("/token/:tokenType", async (req, res) => {
            const allowedTokens = ["file", "register", "avatar"];

            const { tokenType } = req.params;
            if (!allowedTokens.includes(tokenType)) {
                res.sendStatus(401);
                return;
            }

            let scope;

            switch (tokenType) {
                case "file":
                    scope = XTypes.HTTP.TokenScopes.File;
                    break;
                case "register":
                    scope = XTypes.HTTP.TokenScopes.Register;
                    break;
                case "avatar":
                    scope = XTypes.HTTP.TokenScopes.Avatar;
                    break;
                default:
                    res.sendStatus(400);
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

        this.api.get("/file/:id", async (req, res) => {
            const entry = await this.db.retrieveFile(req.params.id);
            if (!entry) {
                res.sendStatus(404);
            } else {
                fs.readFile("files/" + entry.fileID, undefined, (err, file) => {
                    if (err) {
                        this.log.error("error reading file");
                        res.sendStatus(500);
                    } else {
                        const resp: XTypes.HTTP.IFileResponse = {
                            details: entry,
                            data: file,
                        };
                        res.send(resp);
                    }
                });
            }
        });

        this.api.post(
            "/avatar/:userID",
            multer().single("avatar"),
            async (req, res) => {
                const payload: XTypes.HTTP.IFilePayload = req.body;
                const userEntry = await this.db.retrieveUser(req.params.userID);

                if (!userEntry) {
                    res.sendStatus(404);
                    return;
                }

                const token = nacl.sign.open(
                    XUtils.decodeHex(payload.signed),
                    XUtils.decodeHex(userEntry.signKey)
                );
                if (!token) {
                    console.warn("Bad signature on token.");
                    res.sendStatus(401);
                    return;
                }

                try {
                    // write the file to disk
                    fs.writeFile(
                        "avatars/" + userEntry.userID,
                        req.file.buffer,
                        () => {
                            this.log.info(
                                "Wrote new avatar " + userEntry.userID
                            );
                        }
                    );
                    res.sendStatus(200);
                } catch (err) {
                    this.log.warn(err);
                    res.sendStatus(500);
                }
            }
        );

        this.api.get("/canary", async (req, res) => {
            res.send({ canary: process.env.CANARY });
        });

        this.api.post("/file", multer().single("file"), async (req, res) => {
            const payload: XTypes.HTTP.IFilePayload = req.body;

            const userEntry = await this.db.retrieveUser(payload.owner);
            if (!userEntry) {
                console.warn("User does not exist.");
                res.sendStatus(500);
                return;
            }

            const token = nacl.sign.open(
                XUtils.decodeHex(payload.signed),
                XUtils.decodeHex(userEntry.signKey)
            );
            if (!token) {
                console.warn("Bad signature on token.");
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
                this.log.info("Wrote new file " + newFile.fileID);
            });

            await this.db.createFile(newFile);
            res.send(newFile);
        });

        this.api.post("/register/key", (req, res) => {
            try {
                this.log.info("New regkey requested.");
                const regKey = this.createActionToken(
                    XTypes.HTTP.TokenScopes.Register
                );
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
                const regPayload: XTypes.HTTP.IRegPayload = req.body;

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
                        XTypes.HTTP.TokenScopes.Register
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
                                res.status(400).send({
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
                        res.send(user);
                    }
                } else {
                    res.status(400).send({
                        error: "Invalid or no regkey supplied.",
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

/**
 * @ignore
 */
const jestRun = () => {
    return process.env.JEST_WORKER_ID !== undefined;
};
