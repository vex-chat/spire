import { XTypes } from "@vex-chat/types";

export interface ICensoredUser {
    userID: string;
    username: string;
    lastSeen: Date;
}

export const censorUser = (user: XTypes.SQL.IUser): ICensoredUser => {
    return {
        userID: user.userID,
        username: user.username,
        lastSeen: user.lastSeen,
    };
};
