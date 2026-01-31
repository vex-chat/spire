import fs from "fs";
import { Server } from "http";

import { XUtils } from "@vex-chat/crypto";
import * as XTypes from "@vex-chat/types";
import { EventEmitter } from "events";
import express from "express";
import expressWs from "express-ws";

import nacl from "tweetnacl";
import * as uuid from "uuid";
import winston from "winston";
import WebSocket from "ws";

import jwt from "jsonwebtoken";
import { Packr } from "msgpackr";
import { ClientManager } from "./ClientManager";
import { Database, hashPassword } from "./Database";
import { initApp, protect } from "./server";
import { censorUser, ICensoredUser } from "./server/utils";
import { createLogger } from "./utils/createLogger";

const packer = new Packr({ useRecords: false, moreTypes: true });

export const TOKEN_EXPIRY = 1000 * 60 * 10;
export const JWT_EXPIRY = "7d";

const usernameRegex = /^(\w{3,19})$/;

const directories = ["files", "avatars", "emoji"];
for (const dir of directories) {
	if (!fs.existsSync(dir)) {
		fs.mkdirSync(dir);
	}
}

const TokenScopes = XTypes.TokenScopes;

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

function getErrorMessage(error: unknown): string {
	if (error instanceof Error) return error.message;
	return String(error);
}

export class Spire extends EventEmitter {
	private db: Database;
	private clients: ClientManager[] = [];

	// Cast express() to any because express-ws types are strict about the express version
	private expWs: expressWs.Instance = expressWs(express() as any);

	// Force standard Express Application type here to fix the overload errors
	private api: express.Application = this.expWs.app as unknown as express.Application;

	private wss: WebSocket.Server = this.expWs.getWss();

	private signKeys: nacl.SignKeyPair;

	private actionTokens: XTypes.IActionToken[] = [];

	private log: winston.Logger;
	private server: Server | null = null;
	private options: ISpireOptions | undefined;

	constructor(SK: string, options?: ISpireOptions) {
		super();
		this.signKeys = nacl.sign.keyPair.fromSeed(XUtils.decodeHex(SK));

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
					const msg: XTypes.INotifyMsg = {
						transmissionID,
						type: "notify",
						event,
						data,
					};
					client.send(msg);
				}
			} else {
				if (client.getUser().userID === userID) {
					const msg: XTypes.INotifyMsg = {
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
		scope: XTypes.TokenScopes
	): XTypes.IActionToken {
		const token: XTypes.IActionToken = {
			key: uuid.v4(),
			time: new Date(Date.now()),
			scope,
		};
		this.actionTokens.push(token);
		return token;
	}

	private deleteActionToken(key: XTypes.IActionToken) {
		if (this.actionTokens.includes(key)) {
			this.actionTokens.splice(this.actionTokens.indexOf(key), 1);
		}
	}

	private validateToken(
		key: string,
		scope: XTypes.TokenScopes
	): boolean {
		this.log.info("Validating token: " + key);
		for (const rKey of this.actionTokens) {
			if (rKey.key === key) {
				if (rKey.scope !== scope) {
					continue;
				}

				const age =
					new Date(Date.now()).getTime() - rKey.time.getTime();
				this.log.info("Token found, " + age + " ms old.");
				if (age < TOKEN_EXPIRY) {
					this.log.info("Token is valid.");
					this.deleteActionToken(rKey);
					return true;
				} else {
					this.log.info("Token is expired.");
				}
			}
		}
		this.log.info("Token not found.");
		return false;
	}

	private init(apiPort: number): void {
		// Pass standard Express API object to initApp
  		initApp(
  			this.api,
  			this.db,
  			this.log,
  			this.validateToken.bind(this),
  			this.signKeys,
  			this.notify.bind(this)
  		);

  		// Access .ws() from the express-ws instance specifically for websockets
  		// In your Spire class init() method, replace the existing ws handler:

  		this.expWs.app.ws("/socket", async (ws, req) => {
      // Extract auth token
      let authToken: string | undefined;
      const authHeader = req.headers.authorization;

      if (authHeader && typeof authHeader === 'string' && authHeader.startsWith('Bearer ')) {
          authToken = authHeader.substring(7);
      } else {
          authToken = (req as any).cookies?.auth;
      }

      if (!authToken) {
          this.log.warn("User attempted to open socket with no auth token.");
          const err: XTypes.IBaseMsg = {
              type: "unauthorized",
              transmissionID: uuid.v4(),
          };
          ws.send(XUtils.packMessage(err));
          ws.close();
          return;
      }

      // Verify auth JWT
      let userDetails: ICensoredUser;
      try {
          const decoded = jwt.verify(authToken, process.env.SPK!) as any;
          userDetails = decoded.user;

          if (!userDetails || !userDetails.userID) {
              throw new Error("Invalid user data in token");
          }
      } catch (err) {
          this.log.warn("Invalid auth token: " + String(err));
          const errMsg: XTypes.IBaseMsg = {
              type: "unauthorized",
              transmissionID: uuid.v4(),
          };
          ws.send(XUtils.packMessage(errMsg));
          ws.close();
          return;
      }

      // Note: Device authentication happens via challenge/response in ClientManager
      // The device token (if present) could be logged but isn't needed for WebSocket auth
      const deviceToken = req.headers['x-device-token'] as string;
      if (deviceToken) {
          try {
              const decoded = jwt.verify(deviceToken, process.env.SPK!) as any;
              this.log.info("Device token verified for device:", decoded.device?.deviceID);
          } catch (err) {
              this.log.warn("Invalid device token (non-fatal):", String(err));
          }
      }

      this.log.info("New client initiated for user: " + userDetails.username);

      const client = new ClientManager(
          ws,
          this.db,
          this.notify.bind(this),
          userDetails,
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

		this.api.get(
			"/token/:tokenType",
			(req, res, next) => {
				if (req.params.tokenType !== "register") {
					protect(req, res, next);
				} else {
					next();
				}
			},
			async (req, res) => {
				const allowedTokens = [
					"file",
					"register",
					"avatar",
					"device",
					"invite",
					"emoji",
					"connect",
				];

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
					case "invite":
						scope = TokenScopes.Invite;
						break;
					case "emoji":
						scope = TokenScopes.Emoji;
						break;
					case "connect":
						scope = TokenScopes.Connect;
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
					}, TOKEN_EXPIRY);

					return res.send(Buffer.from(packer.pack(token)));
				} catch (err) {
					console.error(getErrorMessage(err));
					return res.sendStatus(500);
				}
			}
		);

		this.api.post("/whoami", protect, async (req, res) => {
      // protect middleware has already verified the token
      // and set req.user
      if (!req.user) {
          res.sendStatus(401);
          return;
      }

      // Get the token from either Authorization header or cookie
      let token: string | undefined;
      const authHeader = req.headers.authorization;

      if (authHeader && typeof authHeader === 'string' && authHeader.startsWith('Bearer ')) {
          token = authHeader.substring(7);
      } else {
          token = req.cookies?.auth;
      }

      if (!token) {
          res.sendStatus(401);
          return;
      }

      // Decode to get expiration
      try {
          const decoded = jwt.verify(token, process.env.SPK!) as any;

          res.send(
              Buffer.from(packer.pack({
                  user: req.user,
                  exp: decoded.exp,
                  token: token,
              }))
          );
      } catch (err) {
          res.sendStatus(401);
      }
  });

		this.api.post("/goodbye", protect, async (req, res) => {
			const signOpts: jwt.SignOptions = { expiresIn: -1 };
			const token = jwt.sign(
				// { user: censorUser(req.user!) },
				{ user: req.user! },
				process.env.SPK!,
				signOpts
			);
			res.cookie("auth", token, { path: "/" });
			res.sendStatus(200);
		});

		this.api.post("/mail", protect, async (req, res) => {
			const senderDeviceDetails = req.device;
			if (!senderDeviceDetails) {
				res.sendStatus(401);
				return;
			}
			const authorUserDetails = req.user!;

			const {
				header,
				mail,
			}: { header: Uint8Array; mail: XTypes.IMailWS } = req.body;

			try {
				await this.db.saveMail(
					mail,
					header,
					senderDeviceDetails.deviceID,
					authorUserDetails.userID
				);
				this.log.info("Received mail for " + mail.recipient);

				const recipientDeviceDetails = await this.db.retrieveDevice(
					mail.recipient
				);
				if (!recipientDeviceDetails) {
					res.sendStatus(400);
					return;
				}

				res.sendStatus(200);
				this.notify(
					recipientDeviceDetails.owner,
					"mail",
					uuid.v4(),
					null,
					mail.recipient
				);
			} catch (err) {
				this.log.error(getErrorMessage(err));
				res.status(500).send(getErrorMessage(err));
			}
		});

		this.api.post("/auth", async (req, res) => {
			const credentials: { username: string; password: string } =
				req.body;

			if (typeof credentials.password !== "string") {
				res.status(400).send(
					"Password is required and must be a string."
				);
				return;
			}

			if (typeof credentials.username !== "string") {
				res.status(400).send(
					"Username is required and must be a string."
				);
				return;
			}

			try {
				const userEntry = await this.db.retrieveUser(
					credentials.username
				);
				if (!userEntry) {
					res.sendStatus(404);
					this.log.warn("User does not exist.");
					return;
				}

				const salt = XUtils.decodeHex(userEntry.passwordSalt);
				const payloadHash = XUtils.encodeHex(
					hashPassword(credentials.password, salt)
				);

				if (payloadHash !== userEntry.passwordHash) {
					res.sendStatus(401);
					return;
				}

				const signOpts: jwt.SignOptions = { expiresIn: JWT_EXPIRY };
				const token = jwt.sign(
					{ user: censorUser(userEntry) },
					process.env.SPK!,
					signOpts
				);

				jwt.verify(token, process.env.SPK!);

				res.cookie("auth", token, { path: "/" });
				res.send(
					Buffer.from(packer.pack({ user: censorUser(userEntry), token }))
				);
			} catch (err) {
				this.log.error(getErrorMessage(err));
				res.sendStatus(500);
			}
		});

		this.api.post("/register", async (req, res) => {
			try {
				const regPayload: XTypes.IRegistrationPayload = req.body;
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
								const errStr = getErrorMessage(err);
								const usernameConflict = errStr
									.includes("users_username_unique");
								const signKeyConflict = errStr
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
								this.log.error(getErrorMessage(err));
								res.sendStatus(500);
								break;
						}
					} else {
						this.log.info("Registration success.");
						res.send(Buffer.from(packer.pack(censorUser(user!))));
					}
				} else {
					res.status(400).send({
						error: "Invalid or no token supplied.",
					});
				}
			} catch (err) {
				this.log.error("error registering user: " + getErrorMessage(err));
				res.sendStatus(500);
			}
		});

		this.server = this.api.listen(apiPort, () => {
			this.log.info("API started on port " + apiPort.toString());
		});
	}
}
