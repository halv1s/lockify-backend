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

/**
 * Check if a subject has a permission on an object.
 * This function works by traversing the ReBAC graph.
 *
 * @param subject - Subject requesting permission (e.g., 'users:userId').
 * @param requiredPermission - Permission to check (e.g., ReBACRelation.EDITOR).
 * @param object - Object the permission is applied on (e.g., 'items:itemId').
 * @param visited - (Internal for recursion) Set to avoid infinite loop in the graph.
 * @returns {Promise<boolean>} - True if has permission, otherwise false.
 */
export const checkPermission = async (
    subject: string,
    requiredPermission: ReBACRelation,
    object: string,
    visited = new Set<string>()
): Promise<boolean> => {
    // Key to prevent infinite recursion
    const visitKey = `${subject}-${requiredPermission}-${object}`;
    if (visited.has(visitKey)) {
        return false;
    }
    visited.add(visitKey);

    // 1. Find all direct relations of the subject.
    const directRelations = await Relation.find({ subject });

    for (const rel of directRelations) {
        // 2. Check direct permission
        // Example: does the user have 'editor' relation on this object?
        if (rel.object === object) {
            // Check if the current relation includes the required permission
            if (
                rel.relation === requiredPermission ||
                permissionHierarchy[rel.relation]?.includes(requiredPermission)
            ) {
                return true;
            }
        }

        // 3. Check permission inherited from parent
        // Example: does the user have 'editor' relation on the parent of this object?
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
                    visited
                )
            ) {
                return true;
            }
        }

        // 4. Check permission by group (User-set rewrites)
        // Example: user is 'manager' of workspace, and the group 'manager' of this workspace has 'editor' permission on object.
        // `rel.object` here is a group, e.g., 'workspaces:wsId'
        // `rel.relation` is the role of user in the group, e.g., 'manager'
        // new subject will be group-role, e.g., 'workspaces:wsId#manager'
        const groupSubject = `${rel.object}#${rel.relation}`;
        if (
            await checkPermission(
                groupSubject,
                requiredPermission,
                object,
                visited
            )
        ) {
            return true;
        }
    }

    return false;
};

// A helper function to use easily from other services
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
