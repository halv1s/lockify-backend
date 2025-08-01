import Workspace from "../models/workspace.model";
import WorkspaceMember from "../models/workspaceMember.model";
import mongoose from "mongoose";

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
    } catch (error: any) {
        throw new Error(`Could not retrieve workspaces: ${error.message}`);
    }
};
