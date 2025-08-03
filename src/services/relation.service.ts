import mongoose from "mongoose";

import Relation from "@/models/relation.model";
import User from "@/models/user.model";
import { hasPermission } from "@/services/permission.service";
import { ReBACNamespace, ReBACRelation } from "@/types";

interface IShareResourceInput {
    initiatorId: string;
    recipientEmail: string;
    targetNamespace: ReBACNamespace;
    targetId: string;
    permissionToGrant: ReBACRelation.EDITOR | ReBACRelation.VIEWER;
    encryptedKey: string;
}

export const shareResource = async (input: IShareResourceInput) => {
    const {
        initiatorId,
        recipientEmail,
        targetNamespace,
        targetId,
        permissionToGrant,
        encryptedKey,
    } = input;

    // 1. Check if the initiator has permission to share (must be an owner)
    const canShare = await hasPermission(
        initiatorId,
        ReBACRelation.OWNER,
        targetNamespace,
        targetId
    );

    if (!canShare) {
        throw new Error("Forbidden: You can only share resources you own.");
    }

    // 2. Find the recipient user
    const recipient = await User.findOne({ email: recipientEmail });
    if (!recipient) {
        throw new Error("Recipient user not found.");
    }
    if ((recipient._id as mongoose.Types.ObjectId).toString() === initiatorId) {
        throw new Error("You cannot share a resource with yourself.");
    }

    // 3. Create or update the relation for the recipient
    const subject = `${ReBACNamespace.USERS}:${recipient._id}`;
    const object = `${targetNamespace}:${targetId}`;

    // Using findOneAndUpdate with upsert is a robust way to handle both new shares
    // and permission updates (e.g., changing a 'viewer' to an 'editor').
    const newRelation = await Relation.findOneAndUpdate(
        {
            subject,
            object,
            // Only modify relations that are for sharing purposes
            relation: { $in: [ReBACRelation.EDITOR, ReBACRelation.VIEWER] },
        },
        {
            $set: {
                subject,
                object,
                relation: permissionToGrant,
                encryptedKey,
            },
        },
        { upsert: true, new: true }
    );

    return newRelation;
};
