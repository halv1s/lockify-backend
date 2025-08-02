import mongoose from "mongoose";

import Folder from "@/models/folder.model";
import Item from "@/models/item.model";
import Share from "@/models/share.model";
import { FolderPermissions, ShareTargetType } from "@/types";

export const hasPermission = async (
    userId: string,
    targetId: string,
    targetType: ShareTargetType,
    requiredPermission: FolderPermissions
): Promise<boolean> => {
    const userObjectId = new mongoose.Types.ObjectId(userId);
    let currentTargetId = new mongoose.Types.ObjectId(targetId);
    let isOwner = false;

    // First, determine if the user is the owner
    if (targetType === ShareTargetType.ITEM) {
        const item = await Item.findById(currentTargetId);
        if (!item) return false;
        if (item.ownerId.equals(userObjectId)) isOwner = true;
    } else {
        const folder = await Folder.findById(currentTargetId);
        if (!folder) return false;
        if (folder.ownerId.equals(userObjectId)) isOwner = true;
    }

    // The owner always has full permissions.
    if (isOwner) return true;

    let highestPermission: FolderPermissions | null = null;

    // If the target is an item, check its direct share first
    if (targetType === ShareTargetType.ITEM) {
        const directItemShare = await Share.findOne({
            userId: userObjectId,
            targetId: currentTargetId,
            targetType: ShareTargetType.ITEM,
        });
        if (directItemShare) {
            highestPermission = directItemShare.permissions;
        }
        // Then, start traversal from its parent folder
        const item = await Item.findById(currentTargetId);
        currentTargetId = item!.folderId;
    }

    // Iteratively check the current folder and its parents
    while (currentTargetId && highestPermission !== FolderPermissions.EDIT) {
        const folderShare = await Share.findOne({
            userId: userObjectId,
            targetId: currentTargetId,
            targetType: ShareTargetType.FOLDER,
        });

        if (folderShare) {
            // 'edit' is higher than 'read-only'
            if (folderShare.permissions === FolderPermissions.EDIT) {
                highestPermission = FolderPermissions.EDIT;
            } else if (!highestPermission) {
                highestPermission = FolderPermissions.READ_ONLY;
            }
        }

        const folder = await Folder.findById(currentTargetId);
        currentTargetId = folder?.parentId as mongoose.Types.ObjectId;
    }

    // Finally, check if the highest permission found meets the requirement
    if (!highestPermission) return false;
    if (requiredPermission === FolderPermissions.EDIT) {
        return highestPermission === FolderPermissions.EDIT;
    }

    // If 'read-only' is required, both 'read-only' and 'edit' are sufficient.
    return true;
};
