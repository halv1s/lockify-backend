import mongoose, { Schema, Document } from "mongoose";
import { FolderPermissions } from "../types";

export interface IFolderMember extends Document {
    folderId: mongoose.Types.ObjectId;
    userId: mongoose.Types.ObjectId;
    permissions: FolderPermissions;
    encryptedFolderKey: string;
}

const folderMemberSchema: Schema = new Schema(
    {
        folderId: {
            type: Schema.Types.ObjectId,
            ref: "Folder",
            required: true,
        },
        userId: {
            type: Schema.Types.ObjectId,
            ref: "User",
            required: true,
        },
        permissions: {
            type: String,
            enum: Object.values(FolderPermissions),
            required: true,
        },
        encryptedFolderKey: {
            type: String,
            required: true,
        },
    },
    {
        timestamps: true,
    }
);

// Prevent a user from being added to the same folder twice.
folderMemberSchema.index({ folderId: 1, userId: 1 }, { unique: true });

export default mongoose.model<IFolderMember>(
    "FolderMember",
    folderMemberSchema
);
