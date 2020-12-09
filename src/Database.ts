import { XUtils } from "@vex-chat/crypto-js";
import { XTypes } from "@vex-chat/types-js";
import log from "electron-log";
import knex from "knex";
import * as uuid from "uuid";

const pubkeyRegex = /[0-9a-f]{64}/;

export class Database {
    private db = knex({
        client: "mysql",
        connection: {
            host: process.env.SQL_HOST,
            user: process.env.SQL_USER,
            password: process.env.SQL_PASSWORD,
            database: process.env.SQL_DB_NAME,
        },
    });

    constructor() {
        this.init();
    }

    public async saveOTK(
        userID: string,
        otk: XTypes.WS.IPreKeys
    ): Promise<void> {
        const newOTK: XTypes.SQL.IPreKeys = {
            keyID: uuid.v4(),
            userID,
            publicKey: XUtils.encodeHex(otk.publicKey),
            signature: XUtils.encodeHex(otk.signature),
            index: otk.index!,
        };
        await this.db("oneTimeKeys").insert(newOTK);
    }

    public async getPreKeys(
        userID: string
    ): Promise<XTypes.WS.IPreKeys | null> {
        const rows: XTypes.SQL.IPreKeys[] = await this.db
            .from("preKeys")
            .select()
            .where({
                userID,
            });
        if (rows.length === 0) {
            return null;
        }
        const [preKeyInfo] = rows;
        const preKey: XTypes.WS.IPreKeys = {
            index: preKeyInfo.index,
            publicKey: XUtils.decodeHex(preKeyInfo.publicKey),
            signature: XUtils.decodeHex(preKeyInfo.signature),
        };
        return preKey;
    }

    public async retrieveUsers(): Promise<XTypes.SQL.IUser[]> {
        return this.db.from("users").select();
    }

    public async getKeyBundle(
        userID: string
    ): Promise<XTypes.WS.IKeyBundle | null> {
        const user = await this.retrieveUser(userID);
        if (!user) {
            log.warn("User not found.");
            return null;
        }
        const otk = (await this.getOTK(userID)) || undefined;
        const preKey = await this.getPreKeys(userID);
        if (!preKey) {
            log.warn("Failed to get prekey.");
            return null;
        }
        const keyBundle: XTypes.WS.IKeyBundle = {
            signKey: XUtils.decodeHex(user.signKey),
            preKey,
            otk,
        };
        return keyBundle;
    }

    public async getOTK(userID: string): Promise<XTypes.WS.IPreKeys | null> {
        const rows: XTypes.SQL.IPreKeys[] = await this.db("oneTimeKeys")
            .select()
            .where({ userID })
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
        };

        // delete the otk
        await this.db
            .from("oneTimeKeys")
            .delete()
            .where({ userID, index: otk.index });

        return otk;
    }

    public async getOTKCount(userID: string): Promise<number> {
        const keys = await this.db
            .from("oneTimeKeys")
            .select()
            .where({ userID });
        return keys.length;
    }

    public async createPermission(
        userID: string,
        resourceType: string,
        resourceID: string,
        powerLevel: number
    ): Promise<XTypes.SQL.IPermission> {
        const permissionID = uuid.v4();

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

    public async retrievePermissions(
        userID: string,
        resourceType: string
    ): Promise<XTypes.SQL.IPermission[]> {
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
        regPayload: XTypes.HTTP.IRegPayload
    ): Promise<[XTypes.SQL.IUser | null, Error | null]> {
        try {
            const user: XTypes.SQL.IUser = {
                userID: uuid.stringify(regKey),
                signKey: regPayload.signKey,
                username: regPayload.username,
                lastSeen: new Date(Date.now()),
            };
            await this.db("users").insert(user);

            const medPreKeys: XTypes.SQL.IPreKeys = {
                keyID: uuid.v4(),
                userID: user.userID,
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

    // the identifier can be username, public key, or userID
    public async retrieveUser(
        userIdentifier: string
    ): Promise<XTypes.SQL.IUser | null> {
        if (uuid.validate(userIdentifier)) {
            const user = await this.db
                .from("users")
                .select()
                .where({ userID: userIdentifier })
                .limit(1);
            if (!user) {
                return null;
            }
            return user[0];
        } else if (pubkeyRegex.test(userIdentifier)) {
            const user = await this.db
                .from("users")
                .select()
                .where({ signKey: userIdentifier })
                .limit(1);
            if (!user) {
                return null;
            }
            return user[0];
        } else {
            const user = await this.db
                .from("users")
                .select()
                .where({ username: userIdentifier })
                .limit(1);
            if (!user) {
                return null;
            }
            return user[0];
        }
    }

    public async saveMail(
        mail: XTypes.WS.IMail,
        header: Uint8Array,
        senderID: string
    ): Promise<void> {
        const entry: XTypes.SQL.IMail = {
            mailType: mail.mailType,
            recipient: mail.recipient,
            sender: senderID,
            cipher: XUtils.encodeHex(mail.cipher),
            nonce: XUtils.encodeHex(mail.nonce),
            extra: XUtils.encodeHex(mail.extra),
            header: XUtils.encodeHex(header),
            time: new Date(Date.now()),
        };

        await this.db("mail").insert(entry);
    }

    public async retrieveMail(
        userID: string
        // tslint:disable-next-line: array-type
    ): Promise<[Uint8Array, XTypes.WS.IMail][]> {
        const rows: XTypes.SQL.IMail[] = await this.db
            .from("mail")
            .select()
            .where({ recipient: userID });

        const mapFunc: (
            row: XTypes.SQL.IMail
        ) => [Uint8Array, XTypes.WS.IMail] = (row) => {
            const msgb: XTypes.WS.IMail = {
                mailType: row.mailType,
                recipient: row.recipient,
                cipher: XUtils.decodeHex(row.cipher),
                nonce: XUtils.decodeHex(row.nonce),
                extra: XUtils.decodeHex(row.extra),
                sender: row.sender,
            };
            const msgh = XUtils.decodeHex(row.header);
            return [msgh, msgb];
        };

        const allMail = rows.map(mapFunc);

        return allMail;
    }

    public async deleteMail(nonce: Uint8Array, userID: string): Promise<void> {
        await this.db
            .from("mail")
            .delete()
            .where({ nonce: XUtils.encodeHex(nonce), recipient: userID });
    }

    public async updateUser(user: XTypes.SQL.IUser): Promise<void> {
        await this.db("users")
            .where({ userID: user.userID })
            .update({
                lastSeen: new Date(Date.now()),
                username: user.username,
            });
    }

    private async init(): Promise<void> {
        if (!(await this.db.schema.hasTable("users"))) {
            await this.db.schema.createTable("users", (table) => {
                table.string("userID").primary();
                table.string("signKey").unique();
                table.string("username").unique();
                table.dateTime("lastSeen");
            });
        }
        if (!(await this.db.schema.hasTable("mail"))) {
            await this.db.schema.createTable("mail", (table) => {
                table.string("nonce").primary();
                table.string("recipient").index();
                table.string("sender");
                table.string("header");
                table.string("cipher");
                table.text("extra");
                table.integer("mailType");
                table.dateTime("time");
            });
        }
        if (!(await this.db.schema.hasTable("preKeys"))) {
            await this.db.schema.createTable("preKeys", (table) => {
                table.string("keyID").primary();
                table.string("userID").index();
                table.string("publicKey");
                table.string("signature");
                table.integer("index");
            });
        }
        if (!(await this.db.schema.hasTable("oneTimeKeys"))) {
            await this.db.schema.createTable("oneTimeKeys", (table) => {
                table.string("keyID").primary();
                table.string("userID").index();
                table.string("publicKey");
                table.string("signature");
                table.integer("index");
            });
        }
        if (!(await this.db.schema.hasTable("servers"))) {
            await this.db.schema.createTable("servers", (table) => {
                table.string("serverID").primary();
                table.string("name");
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
    }
}
