// import { XTypes } from "@vex-chat/types";
import * as XTypes from "@vex-chat/types";

export interface ICensoredUser {
    userID: string;
    username: string;
    lastSeen: Date;
}

export const censorUser = (user: XTypes.IUser): ICensoredUser => {
    return {
        userID: user.userID,
        username: user.username,
        lastSeen: user.lastSeen,
    };
};
