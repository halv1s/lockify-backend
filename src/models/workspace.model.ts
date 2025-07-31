import mongoose, { Schema, Document } from "mongoose";

export interface IWorkspace extends Document {
    ownerId: mongoose.Types.ObjectId;
    name: string;
}

const workspaceSchema: Schema = new Schema(
    {
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
    },
    {
        timestamps: true,
    }
);

export default mongoose.model<IWorkspace>("Workspace", workspaceSchema);
