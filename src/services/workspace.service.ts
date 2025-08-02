import mongoose from "mongoose";

import Workspace from "@/models/workspace.model";
import WorkspaceMember from "@/models/workspaceMember.model";
import { WorkspaceRole } from "@/types";

export const getWorkspacesForUser = async (userId: string) => {
    const memberships = await WorkspaceMember.find({
        userId: new mongoose.Types.ObjectId(userId),
    });

    const workspaceIds = memberships.map((member) => member.workspaceId);

    const workspaces = await Workspace.find({
        _id: { $in: workspaceIds },
    });

    return workspaces;
};

export const createWorkspace = async (ownerId: string, name: string) => {
    const session = await mongoose.startSession();
    session.startTransaction();

    try {
        const newWorkspace = new Workspace({
            ownerId,
            name,
        });
        await newWorkspace.save({ session });

        const newMember = new WorkspaceMember({
            workspaceId: newWorkspace._id,
            userId: ownerId,
            role: WorkspaceRole.ADMIN,
        });
        await newMember.save({ session });

        await session.commitTransaction();
        session.endSession();

        return newWorkspace;
    } catch (error: unknown) {
        await session.abortTransaction();
        session.endSession();
        const errorMessage =
            error instanceof Error ? error.message : "Unknown error";
        throw new Error(`Could not create workspace: ${errorMessage}`);
    }
};
