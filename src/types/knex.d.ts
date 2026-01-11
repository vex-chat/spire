import { Knex } from "knex";
import { 
    IUser, IDevice, IMailSQL, IServer, IChannel, 
    IPermission, IInvite, IEmoji, IFileSQL, IIdentityKeys, IPreKeysSQL 
} from "@vex-chat/types";

declare module "knex" {
    interface Tables {
        users: IUser;
        devices: IDevice;
        mail: IMailSQL;
        servers: IServer;
        channels: IChannel;
        permissions: IPermission;
        invites: IInvite;
        emojis: IEmoji;
        files: IFileSQL;
        preKeys: IPreKeysSQL;
        oneTimeKeys: IPreKeysSQL;
    }
}