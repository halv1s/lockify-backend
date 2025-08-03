import mongoose, { Schema, Document } from "mongoose";

export interface IWorkspace extends Document {
    name: string;
}

const workspaceSchema: Schema = new Schema(
    {
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
