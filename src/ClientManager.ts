// import { sleep } from "@extrahash/sleep";
import { setTimeout as sleep } from "node:timers/promises";
import { xConcat, XUtils } from "@vex-chat/crypto";
import * as XTypes from "@vex-chat/types";
import chalk from "chalk";
import { EventEmitter } from "events";
import { Packr } from "msgpackr"; // CHANGED: msgpackr
import nacl from "tweetnacl";
import {
	parse as uuidParse,
	v4 as uuidv4,
	validate as uuidValidate,
} from "uuid";
import winston from "winston";
import WebSocket from "ws";

import { Database } from "./Database";
import { ICensoredUser } from "./server/utils";
import { ISpireOptions, TOKEN_EXPIRY } from "./Spire";
import { createLogger } from "./utils/createLogger";
import { createUint8UUID } from "./utils/createUint8UUID";

// Instantiate Packer
const packer = new Packr({ useRecords: false, moreTypes: true });

export const POWER_LEVELS = {
	INVITE: 25,
	CREATE: 50,
	DELETE: 50,
	EMOJI: 25,
};

function emptyHeader() {
	return new Uint8Array(32);
}

const MAX_MSG_SIZE = 2048;

function unpackMessage(msg: Buffer): [Uint8Array, XTypes.IBaseMsg] {
	const msgp = Uint8Array.from(msg);
	const msgh = msgp.slice(0, 32);
	// CHANGED: packer.unpack
	const msgb = packer.unpack(msgp.slice(32)) as XTypes.IBaseMsg;
	return [msgh, msgb];
}

function packMessage(msg: any, header?: Uint8Array) {
	// CHANGED: packer.pack
	const msgb = Uint8Array.from(packer.pack(msg));
	const msgh = header || emptyHeader();
	return xConcat(msgh, msgb);
}

export class ClientManager extends EventEmitter {
	private authed: boolean = false;
	private alive: boolean = true;
	private conn: WebSocket;
	private challengeID: Uint8Array = createUint8UUID();
	private failed: boolean = false;
	private db: Database;
	private user: XTypes.IUser | null;
	private userDetails: ICensoredUser;
	private device: XTypes.IDevice | null;
	private log: winston.Logger;
	private notify: (
		userID: string,
		event: string,
		transmissionID: string,
		data?: any,
		deviceID?: string
	) => void;

	constructor(
		ws: WebSocket,
		db: Database,
		notify: (userID: string, event: string, transmissionID: string) => void,
		userDetails: ICensoredUser,
		options?: ISpireOptions
	) {
		super();
		this.conn = ws;
		this.db = db;
		this.user = null;
		this.userDetails = userDetails;
		this.device = null;
		this.notify = notify;
		this.log = createLogger("client-manager", options?.logLevel || "error");

		this.initListeners();
		this.challenge();
	}

	public toString() {
		if (!this.user || !this.device) {
			return "Unauthorized#0000";
		}
		return this.user.username + "<" + this.getDevice().deviceID + ">";
	}

	public getUser(): XTypes.IUser {
		if (!this.authed) {
			throw new Error("You must be authed before getting user info.");
		}
		return this.user!;
	}

	public async send(msg: any, header?: Uint8Array) {
		if (header) {
			this.log.debug(chalk.red.bold("OUTH"), header.toString());
		} else {
			this.log.debug(chalk.red.bold("OUTH"), emptyHeader.toString());
		}

		const packedMessage = packMessage(msg, header);

		this.log.info(
			chalk.bold("⟶   ") +
			responseColor(msg.type.toUpperCase()) +
			" " +
			this.toString() +
			" " +
			chalk.yellow(Buffer.byteLength(packedMessage))
		);

		this.log.debug(chalk.red.bold("OUT"), msg);
		try {
			this.conn.send(packedMessage);
		} catch (err) {
			this.log.warn(String(err));
			this.fail();
		}
	}

	public getDevice(): XTypes.IDevice {
		return this.device!;
	}

	private authorize(transmissionID: string) {
		this.authed = true;
		this.sendAuthedMessage(transmissionID);
		this.db.markDeviceLogin(this.getDevice());
		this.emit("authed");
	}

	private fail() {
		if (this.failed) {
			return;
		}
		if (this.conn) {
			this.log.warn("Connection closed.");
			this.conn.close();
		}
		this.failed = true;
		this.emit("fail");
	}

	private setAlive(status: boolean) {
		this.alive = status;
	}

	private async pingLoop() {
		while (true) {
			this.ping();
			await sleep(5000);
		}
	}

	private ping() {
		if (!this.alive) {
			this.fail();
			return;
		}
		this.setAlive(false);
		const p = { transmissionID: uuidv4(), type: "ping" };
		this.send(p);
	}

	private pong(transmissionID: string) {
		if (this.user) {
			this.db.markUserSeen(this.user);
		}
		const p = { transmissionID, type: "pong" };
		this.send(p);
	}

	private async verifyResponse(msg: XTypes.IRespMsg) {
		const user = await this.db.retrieveUser(this.userDetails.userID);
		if (user) {
			const devices = await this.db.retrieveUserDeviceList([user.userID]);
			let message: Uint8Array | null = null;
			for (const device of devices) {
				const verified = nacl.sign.open(
					msg.signed,
					XUtils.decodeHex(device.signKey)
				);
				if (verified) {
					message = verified;
					this.device = device;
				}
			}
			if (!message) {
				this.log.warn("Signature verification failed!");
				this.sendAuthError(XTypes.SocketAuthErrors.BadSignature);
				this.fail();
				return;
			}

			// if (XUtils.bytesEqual(this.challengeID, message)) {
			if (Buffer.compare(this.challengeID, message) === 0) {
				this.user = user;
				this.authorize(msg.transmissionID);
			} else {
				this.log.warn("Token is bad!");
				this.sendAuthError(XTypes.SocketAuthErrors.InvalidToken);
			}
		} else {
			this.log.info("User is not registered.");
			this.sendAuthError(XTypes.SocketAuthErrors.UserNotRegistered);
			this.fail();
		}
	}

	private challenge() {
		this.challengeID = new Uint8Array(uuidParse(uuidv4()));
		const challenge: XTypes.IChallMsg = {
			transmissionID: uuidv4(),
			type: "challenge",
			challenge: this.challengeID,
		};
		this.send(challenge);
	}

	private sendErr(transmissionID: string, message: string, data?: any) {
		const error: XTypes.IErrMsg = {
			transmissionID,
			type: "error",
			error: message,
			data,
		};
		this.send(error);
	}

	private sendAuthError(error: XTypes.SocketAuthErrors) {
		this.send({ type: "authErr", error });
	}

	private sendAuthedMessage(transmissionID: string) {
		this.send({ type: "authorized", transmissionID });
	}

	private sendSuccess(
		transmissionID: string,
		data: any,
		header?: Uint8Array,
		timestamp?: string
	) {
		const msg: XTypes.ISucessMsg = {
			transmissionID,
			type: "success",
			data,
			timestamp,
		};
		this.send(msg, header);
	}

	private async parseResourceMsg(
		msg: XTypes.IResourceMsg,
		header: Uint8Array
	) {
		switch (msg.resourceType) {
			case "mail":
				if (msg.action === "CREATE") {
					const mail: XTypes.IMailWS = msg.data;

					try {
						await this.db.saveMail(
							mail,
							header,
							this.getDevice().deviceID,
							this.getUser().userID
						);
						this.log.info(
							"Received mail for " + msg.data.recipient
						);

						const deviceDetails = await this.db.retrieveDevice(
							msg.data.recipient
						);
						if (!deviceDetails) {
							this.sendErr(
								msg.transmissionID,
								"No associated user record found for device."
							);
							return;
						}

						this.sendSuccess(msg.transmissionID, null);
						this.notify(
							deviceDetails.owner,
							"mail",
							msg.transmissionID,
							null,
							msg.data.recipient
						);
					} catch (err) {
						this.log.error(err);
						this.sendErr(msg.transmissionID, String(err));
					}
				}
				break;
			default:
				this.log.info("Unsupported resource type " + msg.resourceType);
		}
	}

	private async handleReceipt(msg: XTypes.IReceiptMsg) {
		await this.db.deleteMail(msg.nonce, this.getDevice().deviceID);
	}

	private initListeners() {
		this.conn.on("open", () => {
			setTimeout(() => {
				if (!this.authed) {
					this.conn.close();
				}
			}, TOKEN_EXPIRY);
			this.pingLoop();
		});
		this.conn.on("close", () => {
			this.fail();
		});
		this.conn.on("message", (message: Buffer) => {
			const [header, msg] = unpackMessage(message);
			const size = Buffer.byteLength(message);

			if (size > MAX_MSG_SIZE) {
				this.sendErr(
					msg.transmissionID,
					"Message is too big."
				);
				return;
			}

			// Logging...
			this.log.info(
				chalk.bold("⟵   ") +
				(msg.type === "resource"
					? crudColor(
						(msg as XTypes.IResourceMsg).action.toUpperCase()
					) +
					" " +
					chalk.bold(
						(msg as XTypes.IResourceMsg).resourceType.toUpperCase()
					)
					: chalk.bold(msg.type.toUpperCase())) +
				" " +
				this.toString() +
				" " +
				chalk.yellow(size)
			);

			if (!msg.type || !uuidValidate(msg.transmissionID)) {
				this.sendErr(uuidv4(), "Invalid message format.");
				return;
			}

			switch (msg.type) {
				case "receipt":
					this.handleReceipt(msg as XTypes.IReceiptMsg);
					break;
				case "resource":
					if (!this.authed) {
						this.sendErr(msg.transmissionID, "Not authenticated.");
						break;
					}
					this.parseResourceMsg(msg as XTypes.IResourceMsg, header);
					break;
				case "response":
					this.verifyResponse(msg as XTypes.IRespMsg);
					break;
				case "ping":
					this.pong(msg.transmissionID);
					break;
				case "pong":
					this.setAlive(true);
					break;
				default:
					break;
			}
		});
	}
}

// ... helper colors ...
const crudColor = (action: string): string => {
	switch (action) {
		case "CREATE": return chalk.yellow.bold(action);
		case "RETRIEVE": return chalk.yellow.bold(action);
		case "UPDATE": return chalk.cyan.bold(action);
		case "DELETE": return chalk.red.bold(action);
		default: return action;
	}
};

const responseColor = (status: string): string => {
	switch (status) {
		case "SUCCESS": return chalk.green.bold(status);
		case "ERROR": return chalk.red.bold(status);
		default: return status;
	}
};