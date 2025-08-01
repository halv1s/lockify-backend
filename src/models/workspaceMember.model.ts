import mongoose, { Schema, Document } from "mongoose";

import { WorkspaceRole } from "@/types";

export interface IWorkspaceMember extends Document {
    workspaceId: mongoose.Types.ObjectId;
    userId: mongoose.Types.ObjectId;
    role: WorkspaceRole;
}

const workspaceMemberSchema: Schema = new Schema(
    {
        workspaceId: {
            type: Schema.Types.ObjectId,
            ref: "Workspace",
            required: true,
        },
        userId: {
            type: Schema.Types.ObjectId,
            ref: "User",
            required: true,
        },
        role: {
            type: String,
            enum: Object.values(WorkspaceRole),
            required: true,
        },
    },
    {
        timestamps: true,
    }
);

// Prevent a user from being added to the same workspace twice.
workspaceMemberSchema.index({ workspaceId: 1, userId: 1 }, { unique: true });

export default mongoose.model<IWorkspaceMember>(
    "WorkspaceMember",
    workspaceMemberSchema
);
