import mongoose, { Schema, Document } from "mongoose";

export interface IFolder extends Document {
    workspaceId: mongoose.Types.ObjectId;
    ownerId: mongoose.Types.ObjectId;
    name: string;
    parentId?: mongoose.Types.ObjectId;
    isShared: boolean;
    encryptedSharedFolderKey?: string;
}

const folderSchema: Schema = new Schema(
    {
        workspaceId: {
            type: Schema.Types.ObjectId,
            ref: "Workspace",
            required: true,
        },
        ownerId: {
            type: Schema.Types.ObjectId,
            ref: "User",
            required: true,
        },
        name: {
            type: String,
            required: true,
            trim: true,
        },
        parentId: {
            type: Schema.Types.ObjectId,
            ref: "Folder",
            required: false,
        },
        isShared: {
            type: Boolean,
            default: false,
        },
        encryptedSharedFolderKey: {
            type: String,
            required: false, // Only exists if isShared is true
        },
    },
    {
        timestamps: true,
    }
);

export default mongoose.model<IFolder>("Folder", folderSchema);
