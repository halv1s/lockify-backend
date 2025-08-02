import mongoose from "mongoose";

import Folder from "@/models/folder.model";
import Share from "@/models/share.model";
import User from "@/models/user.model";
import { FolderPermissions, ShareTargetType } from "@/types";

interface IShareResourceInput {
    initiatorId: string;
    recipientEmail: string;
    targetId: string;
    targetType: ShareTargetType;
    permissions: FolderPermissions;
    encryptedKey: string;
}

export const shareResource = async (input: IShareResourceInput) => {
    const {
        initiatorId,
        recipientEmail,
        targetId,
        targetType,
        permissions,
        encryptedKey,
    } = input;

    const recipient = await User.findOne({ email: recipientEmail });
    if (!recipient) {
        throw new Error("Recipient user not found.");
    }
    if ((recipient._id as mongoose.Types.ObjectId).toString() === initiatorId) {
        throw new Error("You cannot share a resource with yourself.");
    }

    if (targetType === ShareTargetType.FOLDER) {
        const folder = await Folder.findById(targetId);
        if (!folder || folder.ownerId.toString() !== initiatorId) {
            throw new Error("Forbidden: You can only share folders you own.");
        }
    }

    // TODO: Add logic for sharing items here later.

    const newShare = await Share.findOneAndUpdate(
        {
            userId: recipient._id,
            targetId: new mongoose.Types.ObjectId(targetId),
            targetType,
        },
        {
            permissions,
            encryptedKey,
        },
        { upsert: true, new: true }
    );

    return newShare;
};
