import mongoose, { Schema, Document } from "mongoose";

export interface IFolder extends Document {
    workspaceId: mongoose.Types.ObjectId;
    name: string;
}

const folderSchema: Schema = new Schema(
    {
        workspaceId: {
            type: Schema.Types.ObjectId,
            ref: "Workspace",
            required: true,
        },
        name: {
            type: String,
            required: true,
            trim: true,
        },
    },
    {
        timestamps: true,
    }
);

export default mongoose.model<IFolder>("Folder", folderSchema);
