import Relation from "@/models/relation.model";
import { ReBACNamespace, ReBACRelation } from "@/types";

const formatIdentifier = (namespace: ReBACNamespace, id: string): string => {
    return `${namespace}:${id}`;
};

const permissionHierarchy: Record<ReBACRelation, ReBACRelation[]> = {
    [ReBACRelation.OWNER]: [
        ReBACRelation.ADMIN,
        ReBACRelation.MANAGER,
        ReBACRelation.MEMBER,
        ReBACRelation.EDITOR,
        ReBACRelation.VIEWER,
    ],
    [ReBACRelation.ADMIN]: [
        ReBACRelation.MANAGER,
        ReBACRelation.MEMBER,
        ReBACRelation.EDITOR,
        ReBACRelation.VIEWER,
    ],
    [ReBACRelation.MANAGER]: [
        ReBACRelation.MEMBER,
        ReBACRelation.EDITOR,
        ReBACRelation.VIEWER,
    ],
    [ReBACRelation.EDITOR]: [ReBACRelation.VIEWER],
    [ReBACRelation.VIEWER]: [],
    [ReBACRelation.MEMBER]: [],
    [ReBACRelation.PARENT]: [],
};

export const checkPermission = async (
    subject: string,
    requiredPermission: ReBACRelation,
    object: string,
    visited = new Set<string>()
): Promise<boolean> => {
    // Anti-cycle mechanism
    const visitKey = `${subject}-${object}`;
    if (visited.has(visitKey)) {
        return false;
    }
    visited.add(visitKey);

    // Find all relations where the current 'subject' is granted some permission.
    const subjectRelations = await Relation.find({ subject });

    for (const rel of subjectRelations) {
        // --- Path 1: Direct Permission Check ---
        // Does this relation apply directly to the object we are checking?
        if (rel.object === object) {
            if (
                rel.relation === requiredPermission ||
                permissionHierarchy[rel.relation]?.includes(requiredPermission)
            ) {
                return true;
            }
        }

        // --- Path 2: Group Permission Check (User-Set Rewrites) ---
        // Does this relation make the user a member of a group? (e.g. subject=user, object=workspace)
        // If so, does that GROUP have the required permission on the target object?
        const groupSubject = `${rel.object}#${rel.relation}`; // e.g., "workspaces:ws123#manager"
        if (
            await checkPermission(
                groupSubject,
                requiredPermission,
                object,
                new Set(visited)
            )
        ) {
            return true;
        }
    }

    // --- Path 3: Parent Inheritance Check ---
    // If no direct or group permissions were found, find the parent of the current object.
    const parentRelation = await Relation.findOne({
        subject: object,
        relation: ReBACRelation.PARENT,
    });
    if (parentRelation) {
        if (
            await checkPermission(
                subject,
                requiredPermission,
                parentRelation.object,
                new Set(visited)
            )
        ) {
            return true;
        }
    }

    return false;
};

export const hasPermission = async (
    userId: string,
    requiredPermission: ReBACRelation,
    objectNamespace: ReBACNamespace,
    objectId: string
): Promise<boolean> => {
    const subject = formatIdentifier(ReBACNamespace.USERS, userId);
    const object = formatIdentifier(objectNamespace, objectId);

    return checkPermission(subject, requiredPermission, object);
};
