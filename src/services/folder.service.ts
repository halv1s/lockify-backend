import mongoose from "mongoose";

import Folder from "@/models/folder.model";
import WorkspaceMember from "@/models/workspaceMember.model";
import { WorkspaceRole } from "@/types";

export const getFolders = async (userId: string, workspaceId: string) => {
    const membership = await WorkspaceMember.findOne({
        workspaceId: new mongoose.Types.ObjectId(workspaceId),
        userId: new mongoose.Types.ObjectId(userId),
    });

    if (!membership) {
        throw new Error("Forbidden: User is not a member of this workspace.");
    }

    const folders = await Folder.find({
        workspaceId: new mongoose.Types.ObjectId(workspaceId),
    });

    return folders;
};

export const createFolder = async (
    ownerId: string,
    workspaceId: string,
    name: string,
    parentId?: string
) => {
    const membership = await WorkspaceMember.findOne({
        workspaceId: new mongoose.Types.ObjectId(workspaceId),
        userId: new mongoose.Types.ObjectId(ownerId),
    });

    if (!membership) {
        throw new Error("Forbidden: User is not a member of this workspace.");
    }

    if (
        membership.role !== WorkspaceRole.ADMIN &&
        membership.role !== WorkspaceRole.MANAGER
    ) {
        throw new Error(
            "Forbidden: Only workspace admins or managers can create new folders."
        );
    }

    if (parentId) {
        const parentFolder = await Folder.findOne({
            _id: parentId,
            workspaceId: workspaceId,
        });
        if (!parentFolder) {
            throw new Error(
                "Parent folder not found or does not belong to the specified workspace."
            );
        }
    }

    const newFolder = new Folder({
        ownerId,
        workspaceId,
        name,
        parentId,
    });

    await newFolder.save();
    return newFolder;
};
