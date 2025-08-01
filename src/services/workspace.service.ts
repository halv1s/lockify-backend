import mongoose from "mongoose";

import Workspace from "../models/workspace.model";
import WorkspaceMember from "../models/workspaceMember.model";

export const getWorkspacesForUser = async (userId: string) => {
    try {
        const memberships = await WorkspaceMember.find({
            userId: new mongoose.Types.ObjectId(userId),
        });

        const workspaceIds = memberships.map((member) => member.workspaceId);

        const workspaces = await Workspace.find({
            _id: { $in: workspaceIds },
        });

        return workspaces;
    } catch (error: unknown) {
        const errorMessage =
            error instanceof Error ? error.message : "Unknown error";
        throw new Error(`Could not retrieve workspaces: ${errorMessage}`);
    }
};
