import { xMakeNonce, XUtils } from "@vex-chat/crypto";
import { XTypes } from "@vex-chat/types";
import { EventEmitter } from "events";
import knex from "knex";
import pbkdf2 from "pbkdf2";
import * as uuid from "uuid";
import winston from "winston";
import { ISpireOptions } from "./Spire";
import { createLogger } from "./utils/createLogger";

const pubkeyRegex = /[0-9a-f]{64}/;
export const ITERATIONS = 1000;

export class Database extends EventEmitter {
    private db: knex<any, unknown[]>;
    private log: winston.Logger;

    constructor(options?: ISpireOptions) {
        super();

        this.log = createLogger("spire-db", options?.logLevel || "error");

        switch (options?.dbType || "mysql") {
            case "sqlite3":
                this.db = knex({
                    client: "sqlite3",
                    connection: {
                        filename: "spire.sqlite",
                    },
                    useNullAsDefault: true,
                });
                break;
            case "sqlite3mem":
                this.db = knex({
                    client: "sqlite3",
                    connection: {
                        filename: ":memory:",
                    },
                    useNullAsDefault: true,
                });
                break;
            case "mysql":
            default:
                this.db = knex({
                    client: "mysql",
                    connection: {
                        host: process.env.SQL_HOST,
                        user: process.env.SQL_USER,
                        password: process.env.SQL_PASSWORD,
                        database: process.env.SQL_DB_NAME,
                    },
                });
                break;
        }

        this.init();
    }

    public async saveOTK(
        userID: string,
        otk: XTypes.WS.IPreKeys
    ): Promise<void> {
        const newOTK: XTypes.SQL.IPreKeys = {
            keyID: uuid.v4(),
            userID,
            deviceID: otk.deviceID,
            publicKey: XUtils.encodeHex(otk.publicKey),
            signature: XUtils.encodeHex(otk.signature),
            index: otk.index!,
        };
        await this.db("oneTimeKeys").insert(newOTK);
    }

    public async getPreKeys(
        deviceID: string
    ): Promise<XTypes.WS.IPreKeys | null> {
        const rows: XTypes.SQL.IPreKeys[] = await this.db
            .from("preKeys")
            .select()
            .where({
                deviceID,
            });
        if (rows.length === 0) {
            return null;
        }
        const [preKeyInfo] = rows;
        const preKey: XTypes.WS.IPreKeys = {
            index: preKeyInfo.index,
            publicKey: XUtils.decodeHex(preKeyInfo.publicKey),
            signature: XUtils.decodeHex(preKeyInfo.signature),
            deviceID: preKeyInfo.deviceID,
        };
        return preKey;
    }

    public async retrieveUsers(): Promise<XTypes.SQL.IUser[]> {
        return this.db.from("users").select();
    }

    public async getKeyBundle(
        deviceID: string
    ): Promise<XTypes.WS.IKeyBundle | null> {
        const device = await this.retrieveDevice(deviceID);
        if (!device) {
            throw new Error("DeviceID not found.");
        }
        const otk = (await this.getOTK(deviceID)) || undefined;
        const preKey = await this.getPreKeys(deviceID);
        if (!preKey) {
            throw new Error("Failed to get prekey.");
        }
        const keyBundle: XTypes.WS.IKeyBundle = {
            signKey: XUtils.decodeHex(device.signKey),
            preKey,
            otk,
        };
        return keyBundle;
    }

    public async createDevice(
        owner: string,
        payload: XTypes.HTTP.IDevicePayload
    ): Promise<XTypes.SQL.IDevice> {
        const device = {
            owner,
            signKey: payload.signKey,
            deviceID: uuid.v4(),
            name: payload.deviceName,
            lastLogin: new Date(Date.now()).toString(),
        };

        try {
            await this.db("devices").insert(device);
        } catch (err) {
            if (err.errno !== 19) {
                throw err;
            }
            this.log.warn("Attempted to insert duplicate deviceID.");
        }

        const medPreKeys: XTypes.SQL.IPreKeys = {
            keyID: uuid.v4(),
            userID: owner,
            deviceID: device.deviceID,
            publicKey: payload.preKey,
            signature: payload.preKeySignature,
            index: payload.preKeyIndex,
        };

        await this.db("preKeys").insert(medPreKeys);

        return device;
    }

    public async deleteDevice(deviceID: string): Promise<void> {
        return this.db
            .from("devices")
            .where({ deviceID })
            .del();
    }

    public async retrieveDevice(
        deviceID: string
    ): Promise<XTypes.SQL.IDevice | null> {
        if (uuid.validate(deviceID)) {
            const rows = await this.db
                .from("devices")
                .select()
                .where({ deviceID });
            if (rows.length === 0) {
                return null;
            }
            const [device] = rows;
            return device;
        }
        if (pubkeyRegex.test(deviceID)) {
            const rows = await this.db
                .from("devices")
                .select()
                .where({ signKey: deviceID });
            if (rows.length === 0) {
                return null;
            }
            const [device] = rows;
            return device;
        }
        return null;
    }

    public async retrieveUserDeviceList(
        userIDs: string[]
    ): Promise<XTypes.SQL.IDevice[]> {
        return this.db
            .from("devices")
            .select()
            .whereIn("owner", userIDs);
    }

    public async getOTK(deviceID: string): Promise<XTypes.WS.IPreKeys | null> {
        // while (this.otkQueue.includes(deviceID)) {
        //     console.warn("deviceID locked, waiting.");
        //     console.warn(this.otkQueue);
        //     await sleep(100);
        // }
        // this.otkQueue.push(deviceID);
        const rows: XTypes.SQL.IPreKeys[] = await this.db("oneTimeKeys")
            .select()
            .where({ deviceID })
            .limit(1)
            .orderBy("index");
        if (rows.length === 0) {
            return null;
        }
        const [otkInfo] = rows;
        const otk: XTypes.WS.IPreKeys = {
            publicKey: XUtils.decodeHex(otkInfo.publicKey),
            signature: XUtils.decodeHex(otkInfo.signature),
            index: otkInfo.index,
            deviceID: otkInfo.deviceID,
        };

        try {
            // delete the otk
            await this.db
                .from("oneTimeKeys")
                .delete()
                .where({ deviceID, index: otk.index });
            return otk;
        } catch (err) {
            throw err;
        }
    }

    public async getOTKCount(deviceID: string): Promise<number> {
        const keys = await this.db
            .from("oneTimeKeys")
            .select()
            .where({ deviceID });
        return keys.length;
    }

    public async createPermission(
        userID: string,
        resourceType: string,
        resourceID: string,
        powerLevel: number
    ): Promise<XTypes.SQL.IPermission> {
        const permissionID = uuid.v4();

        // check if it already exists
        const checkPermission = await this.db
            .from("permissions")
            .select()
            .where({ userID, resourceID });
        if (checkPermission.length > 0) {
            return checkPermission[0];
        }

        const permission: XTypes.SQL.IPermission = {
            permissionID,
            userID,
            resourceType,
            resourceID,
            powerLevel,
        };

        await this.db("permissions").insert(permission);
        return permission;
    }

    public async retrieveInvite(
        inviteID: string
    ): Promise<XTypes.SQL.IInvite | null> {
        const rows = await this.db
            .from("invites")
            .select()
            .where({ inviteID });
        if (rows.length === 0) {
            return null;
        }
        return rows[0];
    }

    public async retrieveServerInvites(
        serverID: string
    ): Promise<XTypes.SQL.IInvite[]> {
        return this.db
            .from("invites")
            .select()
            .where({ serverID });
    }

    public async deleteInvite(inviteID: string): Promise<void> {
        await this.db
            .from("invites")
            .where({ inviteID })
            .delete();
    }

    public async createInvite(
        inviteID: string,
        serverID: string,
        ownerID: string,
        expiration: string
    ): Promise<XTypes.SQL.IInvite> {
        const invite: XTypes.SQL.IInvite = {
            inviteID,
            serverID,
            owner: ownerID,
            expiration,
        };

        await this.db("invites").insert(invite);
        return invite;
    }

    public async retrieveGroupMembers(
        channelID: string
    ): Promise<XTypes.SQL.IUser[]> {
        const channel = await this.retrieveChannel(channelID);
        if (!channel) {
            return [];
        }
        const permissions: XTypes.SQL.IPermission[] = await this.db
            .from("permissions")
            .select()
            .where({ resourceID: channel.serverID });

        const groupMembers: XTypes.SQL.IUser[] = [];
        for (const permission of permissions) {
            const user = await this.retrieveUser(permission.userID);
            if (user) {
                groupMembers.push(user);
            }
        }

        return groupMembers;
    }

    public async retrieveChannel(
        channelID: string
    ): Promise<XTypes.SQL.IChannel | null> {
        const channels: XTypes.SQL.IChannel[] = await this.db
            .from("channels")
            .select()
            .where({ channelID })
            .limit(1);

        if (channels.length === 0) {
            return null;
        }
        return channels[0];
    }

    public async retrieveChannels(
        serverID: string
    ): Promise<XTypes.SQL.IChannel[]> {
        const channels: XTypes.SQL.IChannel[] = await this.db
            .from("channels")
            .select()
            .where({ serverID });
        return channels;
    }

    public async createChannel(
        name: string,
        serverID: string
    ): Promise<XTypes.SQL.IChannel> {
        const channel: XTypes.SQL.IChannel = {
            channelID: uuid.v4(),
            serverID,
            name,
        };
        await this.db("channels").insert(channel);
        return channel;
    }

    public async createServer(
        name: string,
        ownerID: string
    ): Promise<XTypes.SQL.IServer> {
        // create the server
        const server: XTypes.SQL.IServer = {
            name,
            serverID: uuid.v4(),
        };
        await this.db("servers").insert(server);
        // create the admin permission
        await this.createPermission(ownerID, "server", server.serverID, 100);
        // create the general channel
        await this.createChannel("general", server.serverID);
        return server;
    }

    /**
     * Retrives a list of users that should be notified when a specific resourceID
     * experiences changes.
     *
     * @param resourceID
     */
    public async retrieveAffectedUsers(
        resourceID: string
    ): Promise<XTypes.SQL.IUser[]> {
        const permissionList = await this.retrievePermissionsByResourceID(
            resourceID
        );

        const users: XTypes.SQL.IUser[] = [];
        for (const permission of permissionList) {
            const user = await this.retrieveUser(permission.userID);
            if (user) {
                users.push(user);
            }
        }

        return users;
    }

    public async retrievePermissionsByResourceID(
        resourceID: string
    ): Promise<XTypes.SQL.IPermission[]> {
        return this.db
            .from("permissions")
            .select()
            .where({ resourceID });
    }

    public async retrievePermissions(
        userID: string,
        resourceType: string
    ): Promise<XTypes.SQL.IPermission[]> {
        if (resourceType === "all") {
            const sList = await this.db
                .from("permissions")
                .select()
                .where({ userID });
            return sList;
        }
        const serverList = await this.db
            .from("permissions")
            .select()
            .where({ userID, resourceType });
        return serverList;
    }

    public async retrieveServer(
        serverID: string
    ): Promise<XTypes.SQL.IServer | null> {
        const rows = await this.db
            .from("servers")
            .select()
            .where({ serverID })
            .limit(1);
        if (rows.length === 0) {
            return null;
        }
        const server: XTypes.SQL.IServer = rows[0];
        return server;
    }

    public async deletePermissions(resourceID: string): Promise<void> {
        await this.db
            .from("permissions")
            .where({ resourceID })
            .delete();
    }

    public async deletePermission(permissionID: string): Promise<void> {
        await this.db
            .from("permissions")
            .where({ permissionID })
            .delete();
    }

    public async retrievePermission(
        permissionID: string
    ): Promise<XTypes.SQL.IPermission | null> {
        const rows = await this.db
            .from("permissions")
            .where({ permissionID })
            .select();

        if (rows.length === 0) {
            return null;
        }

        return rows[0];
    }

    public async deleteChannel(channelID: string): Promise<void> {
        await this.deletePermissions(channelID);
        await this.db
            .from("mail")
            .where({ group: channelID })
            .delete();
        await this.db
            .from("channels")
            .where({ channelID })
            .delete();
    }

    public async createEmoji(emoji: XTypes.SQL.IEmoji): Promise<void> {
        await this.db("emojis").insert(emoji);
    }

    public async deleteEmoji(emojiID: string): Promise<void> {
        await this.db
            .from("emojis")
            .where({ emojiID })
            .del();
    }

    public async retrieveEmojiList(
        userID: string
    ): Promise<XTypes.SQL.IEmoji[]> {
        return this.db
            .from("emojis")
            .select()
            .where({ owner: userID });
    }

    public async retrieveEmoji(
        emojiID: string
    ): Promise<XTypes.SQL.IEmoji | null> {
        const rows = await this.db
            .from("emojis")
            .select()
            .where({ emojiID });
        if (rows.length === 0) {
            return null;
        }
        return rows[0];
    }

    public async deleteServer(serverID: string): Promise<void> {
        await this.deletePermissions(serverID);
        const channels = await this.retrieveChannels(serverID);
        for (const channel of channels) {
            await this.deleteChannel(channel.channelID);
        }
        await this.db
            .from("servers")
            .where({ serverID })
            .delete();
    }

    public async retrieveServers(
        userID: string
    ): Promise<XTypes.SQL.IServer[]> {
        const serverPerms = await this.retrievePermissions(userID, "server");
        if (!serverPerms) {
            return [];
        }
        const serverList: XTypes.SQL.IServer[] = [];
        for (const perm of serverPerms) {
            const server = await this.retrieveServer(perm.resourceID);
            if (server) {
                serverList.push(server);
            }
        }
        return serverList;
    }

    public async createUser(
        regKey: Uint8Array,
        regPayload: XTypes.HTTP.IDevicePayload
    ): Promise<[XTypes.SQL.IUser | null, Error | null]> {
        try {
            const salt = xMakeNonce();
            const passwordHash = hashPassword(regPayload.password, salt);

            const user: XTypes.SQL.IUser = {
                userID: uuid.stringify(regKey),
                username: regPayload.username,
                lastSeen: new Date(Date.now()),
                passwordHash: passwordHash.toString("hex"),
                passwordSalt: XUtils.encodeHex(salt),
            };

            await this.db("users").insert(user);
            const device = await this.createDevice(user.userID, regPayload);

            const medPreKeys: XTypes.SQL.IPreKeys = {
                keyID: uuid.v4(),
                userID: user.userID,
                deviceID: device.deviceID,
                publicKey: regPayload.preKey,
                signature: regPayload.preKeySignature,
                index: regPayload.preKeyIndex,
            };

            await this.db("preKeys").insert(medPreKeys);
            return [user, null];
        } catch (err) {
            return [null, err];
        }
    }

    public async createFile(file: XTypes.SQL.IFile): Promise<void> {
        return this.db("files").insert(file);
    }

    public async retrieveFile(
        fileID: string
    ): Promise<XTypes.SQL.IFile | null> {
        const file = await this.db
            .from("files")
            .select()
            .where({ fileID });
        if (file.length === 0) {
            return null;
        }
        return file[0];
    }

    // the identifier can be username, public key, or userID
    public async retrieveUser(
        userIdentifier: string
    ): Promise<XTypes.SQL.IUser | null> {
        let rows: XTypes.SQL.IUser[] = [];
        if (uuid.validate(userIdentifier)) {
            rows = await this.db
                .from("users")
                .select()
                .where({ userID: userIdentifier })
                .limit(1);
        } else {
            rows = await this.db
                .from("users")
                .select()
                .where({ username: userIdentifier })
                .limit(1);
        }

        if (rows.length === 0) {
            return null;
        }
        const [user] = rows;
        return user;
    }

    public async saveMail(
        mail: XTypes.WS.IMail,
        header: Uint8Array,
        deviceID: string,
        userID: string
    ): Promise<void> {
        const entry: XTypes.SQL.IMail = {
            mailID: mail.mailID,
            mailType: mail.mailType,
            recipient: mail.recipient,
            sender: deviceID,
            cipher: XUtils.encodeHex(mail.cipher),
            nonce: XUtils.encodeHex(mail.nonce),
            extra: XUtils.encodeHex(mail.extra),
            header: XUtils.encodeHex(header),
            time: new Date(Date.now()),
            group: mail.group ? XUtils.encodeHex(mail.group) : null,
            forward: mail.forward,
            authorID: userID,
            readerID: mail.readerID,
        };

        await this.db("mail").insert(entry);
    }

    public async retrieveMail(
        deviceID: string
        // tslint:disable-next-line: array-type
    ): Promise<[Uint8Array, XTypes.WS.IMail, Date][]> {
        const rows: XTypes.SQL.IMail[] = await this.db
            .from("mail")
            .select()
            .where({ recipient: deviceID });

        const fixMail: (
            mail: XTypes.SQL.IMail
        ) => [Uint8Array, XTypes.WS.IMail, Date] = (mail) => {
            const msgb: XTypes.WS.IMail = {
                mailType: mail.mailType,
                mailID: mail.mailID,
                recipient: mail.recipient,
                cipher: XUtils.decodeHex(mail.cipher),
                nonce: XUtils.decodeHex(mail.nonce),
                extra: XUtils.decodeHex(mail.extra),
                sender: mail.sender,
                group: mail.group ? XUtils.decodeHex(mail.group) : null,
                forward: Boolean(mail.forward),
                authorID: mail.authorID,
                readerID: mail.readerID,
            };

            const msgh = XUtils.decodeHex(mail.header);
            return [msgh, msgb, new Date(mail.time)];
        };

        const allMail = rows.map(fixMail);

        return allMail;
    }

    public async deleteMail(nonce: Uint8Array, userID: string): Promise<void> {
        await this.db
            .from("mail")
            .delete()
            .where({ nonce: XUtils.encodeHex(nonce), recipient: userID });
    }

    public async markUserSeen(user: XTypes.SQL.IUser): Promise<void> {
        await this.db("users")
            .where({ userID: user.userID })
            .update({
                lastSeen: new Date(Date.now()),
            });
    }

    public async markDeviceLogin(device: XTypes.SQL.IDevice): Promise<void> {
        await this.db("users")
            .where({ deviceID: device.deviceID })
            .update({
                lastLogin: new Date(Date.now()),
            });
    }

    public async close(): Promise<void> {
        this.log.info("Closing database.");
        await this.db.destroy();
    }

    private async init(): Promise<void> {
        if (!(await this.db.schema.hasTable("invites"))) {
            await this.db.schema.createTable("invites", (table) => {
                table.string("inviteID").primary();
                table.string("serverID").index();
                table.string("owner");
                table.string("expiration");
            });
        }

        if (!(await this.db.schema.hasTable("users"))) {
            await this.db.schema.createTable("users", (table) => {
                table.string("userID").primary();
                table.string("username").unique();
                table.string("passwordHash");
                table.string("passwordSalt");
                table.dateTime("lastSeen");
            });
        }
        if (!(await this.db.schema.hasTable("devices"))) {
            await this.db.schema.createTable("devices", (table) => {
                table.string("deviceID").primary();
                table.string("signKey").unique();
                table.string("owner");
                table.string("name");
                table.string("lastLogin");
            });
        }
        if (!(await this.db.schema.hasTable("mail"))) {
            await this.db.schema.createTable("mail", (table) => {
                table.string("nonce").primary();
                table.string("recipient").index();
                table.string("mailID");
                table.string("sender");
                table.string("header");
                table.text("cipher", "mediumtext");
                table.string("group");
                table.text("extra");
                table.integer("mailType");
                table.dateTime("time");
                table.boolean("forward");
                table.string("authorID");
                table.string("readerID");
            });
        }
        if (!(await this.db.schema.hasTable("preKeys"))) {
            await this.db.schema.createTable("preKeys", (table) => {
                table.string("keyID").primary();
                table.string("userID").index();
                table.string("deviceID").index();
                table.string("publicKey");
                table.string("signature");
                table.integer("index");
            });
        }
        if (!(await this.db.schema.hasTable("oneTimeKeys"))) {
            await this.db.schema.createTable("oneTimeKeys", (table) => {
                table.string("keyID").primary();
                table.string("userID").index();
                table.string("deviceID").index();
                table.string("publicKey");
                table.string("signature");
                table.integer("index");
            });
        }
        if (!(await this.db.schema.hasTable("servers"))) {
            await this.db.schema.createTable("servers", (table) => {
                table.string("serverID").primary();
                table.string("name");
                table.string("icon");
            });
        }
        if (!(await this.db.schema.hasTable("channels"))) {
            await this.db.schema.createTable("channels", (table) => {
                table.string("channelID").primary();
                table.string("serverID");
                table.string("name");
            });
        }
        if (!(await this.db.schema.hasTable("permissions"))) {
            await this.db.schema.createTable("permissions", (table) => {
                table.string("permissionID").primary();
                table.string("userID").index();
                table.string("resourceType");
                table.string("resourceID").index();
                table.integer("powerLevel");
            });
        }

        if (!(await this.db.schema.hasTable("files"))) {
            await this.db.schema.createTable("files", (table) => {
                table.string("fileID").primary();
                table.string("owner").index();
                table.string("nonce");
            });
        }

        if (!(await this.db.schema.hasTable("emojis"))) {
            await this.db.schema.createTable("emojis", (table) => {
                table.string("emojiID").primary();
                table.string("owner").index();
                table.string("name");
            });
        }

        this.emit("ready");
    }
}

export const hashPassword = (password: string, salt: Uint8Array) =>
    pbkdf2.pbkdf2Sync(password, salt, ITERATIONS, 32, "sha512");
