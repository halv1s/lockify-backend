import mongoose, { Schema, Document } from "mongoose";

import { FolderPermissions, ShareTargetType } from "@/types";

export interface IShare extends Document {
    userId: mongoose.Types.ObjectId;
    targetId: mongoose.Types.ObjectId;
    targetType: ShareTargetType;
    permissions: FolderPermissions;
    encryptedKey: string;
}

const shareSchema: Schema = new Schema(
    {
        userId: {
            type: Schema.Types.ObjectId,
            ref: "User",
            required: true,
        },
        targetId: {
            type: Schema.Types.ObjectId,
            required: true,
        },
        targetType: {
            type: String,
            enum: Object.values(ShareTargetType),
            required: true,
        },
        permissions: {
            type: String,
            enum: Object.values(FolderPermissions),
            required: true,
        },
        encryptedKey: {
            type: String,
            required: true,
        },
    },
    {
        timestamps: true,
    }
);

// Prevent a user from being shared the same item/folder twice
shareSchema.index({ userId: 1, targetId: 1, targetType: 1 }, { unique: true });

export default mongoose.model<IShare>("Share", shareSchema);
