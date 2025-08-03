import mongoose from "mongoose";

import Relation from "@/models/relation.model";
import Workspace from "@/models/workspace.model";
import { ReBACNamespace, ReBACRelation } from "@/types";

export const getWorkspacesForUser = async (userId: string) => {
    const userSubject = `${ReBACNamespace.USERS}:${userId}`;
    const memberships = await Relation.find({
        subject: userSubject,
        object: new RegExp(`^${ReBACNamespace.WORKSPACES}:`),
    });

    const workspaceIds = memberships.map((member) => {
        return new mongoose.Types.ObjectId(member.object.split(":")[1]);
    });

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
            name,
        });
        await newWorkspace.save({ session });

        const ownerSubject = `${ReBACNamespace.USERS}:${ownerId}`;
        const workspaceObject = `${ReBACNamespace.WORKSPACES}:${newWorkspace._id}`;

        const relationsToCreate = [
            {
                subject: ownerSubject,
                relation: ReBACRelation.OWNER,
                object: workspaceObject,
            },
            {
                subject: ownerSubject,
                relation: ReBACRelation.ADMIN,
                object: workspaceObject,
            },
        ];

        await Relation.insertMany(relationsToCreate, { session });

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
