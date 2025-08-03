import mongoose from "mongoose";

import Folder from "@/models/folder.model";
import Relation from "@/models/relation.model";
import { hasPermission } from "@/services/permission.service";
import { ReBACNamespace, ReBACRelation } from "@/types";

export const getFolders = async (userId: string, workspaceId: string) => {
    const canAccessWorkspace = await hasPermission(
        userId,
        ReBACRelation.MEMBER,
        ReBACNamespace.WORKSPACES,
        workspaceId
    );

    if (!canAccessWorkspace) {
        throw new Error("Forbidden: User is not a member of this workspace.");
    }

    const folders = await Folder.find({
        workspaceId: new mongoose.Types.ObjectId(workspaceId),
    });

    return folders;
};

export const createFolder = async (
    creatorId: string,
    workspaceId: string,
    name: string,
    parentId?: string
) => {
    const canCreateFolder = await hasPermission(
        creatorId,
        ReBACRelation.MANAGER,
        ReBACNamespace.WORKSPACES,
        workspaceId
    );

    if (!canCreateFolder) {
        throw new Error(
            "Forbidden: Only workspace admins or managers can create new folders."
        );
    }

    const session = await mongoose.startSession();
    session.startTransaction();

    try {
        if (parentId) {
            const parentFolder = await Folder.findOne({
                _id: parentId,
                workspaceId: workspaceId,
            }).session(session);
            if (!parentFolder) {
                throw new Error(
                    "Parent folder not found or does not belong to the specified workspace."
                );
            }
        }

        const newFolder = new Folder({
            workspaceId,
            name,
        });
        await newFolder.save({ session });

        const userSubject = `${ReBACNamespace.USERS}:${creatorId}`;
        const folderObject = `${ReBACNamespace.FOLDERS}:${newFolder._id}`;

        const relationsToCreate = [
            {
                subject: userSubject,
                relation: ReBACRelation.OWNER,
                object: folderObject,
            },
        ];

        if (parentId) {
            relationsToCreate.push({
                subject: folderObject,
                relation: ReBACRelation.PARENT,
                object: `${ReBACNamespace.FOLDERS}:${parentId}`,
            });
        }

        await Relation.insertMany(relationsToCreate, { session });

        await session.commitTransaction();
        session.endSession();

        return newFolder;
    } catch (error: unknown) {
        await session.abortTransaction();
        session.endSession();
        throw error;
    }
};
