import mongoose from "mongoose";

import Folder from "@/models/folder.model";
import Item, { IItem } from "@/models/item.model";
import WorkspaceMember from "@/models/workspaceMember.model";
import * as permissionService from "@/services/permission.service";
import { FolderPermissions, ItemType, ShareTargetType } from "@/types";

export const getItemsInFolder = async (userId: string, folderId: string) => {
    const folder = await Folder.findById(folderId);
    if (!folder) {
        throw new Error("Folder not found.");
    }

    const membership = await WorkspaceMember.findOne({
        workspaceId: folder.workspaceId,
        userId: new mongoose.Types.ObjectId(userId),
    });

    if (!membership) {
        throw new Error(
            "Forbidden: You do not have access to this folder's workspace."
        );
    }

    // Fetch only the necessary metadata for the list view (lazy loading).
    // We explicitly exclude the sensitive encrypted fields.
    const items = await Item.find({ folderId }).select(
        "-encryptedData -encryptedRecordKey"
    );

    return items;
};

export const getItemById = async (
    userId: string,
    itemId: string
): Promise<IItem> => {
    const hasReadAccess = await permissionService.hasPermission(
        userId,
        itemId,
        ShareTargetType.ITEM,
        FolderPermissions.READ_ONLY
    );
    if (!hasReadAccess) {
        throw new Error(
            "Forbidden: You do not have permission to access this item."
        );
    }
    const item = await Item.findById(itemId);
    if (!item) throw new Error("Item not found.");
    return item;
};

interface ICreateItemInput {
    ownerId: string;
    folderId: string;
    type: ItemType;
    displayMetadata?: object;
    encryptedData: string;
    encryptedDataIv: string;
    encryptedRecordKey: string;
    encryptedRecordKeyIv: string;
}

export const createItem = async (input: ICreateItemInput): Promise<IItem> => {
    const {
        ownerId,
        folderId,
        type,
        displayMetadata,
        encryptedData,
        encryptedDataIv,
        encryptedRecordKey,
        encryptedRecordKeyIv,
    } = input;

    const hasEditPermission = await permissionService.hasPermission(
        ownerId,
        folderId,
        ShareTargetType.FOLDER,
        FolderPermissions.EDIT
    );

    if (!hasEditPermission) {
        throw new Error(
            "Forbidden: You do not have permission to create items in this folder."
        );
    }

    const newItem = new Item({
        ownerId,
        folderId,
        type,
        displayMetadata,
        encryptedData,
        encryptedDataIv,
        encryptedRecordKey,
        encryptedRecordKeyIv,
    });

    await newItem.save();
    return newItem;
};

interface IUpdateItemInput {
    displayMetadata?: object;
    encryptedData?: string;
    encryptedDataIv?: string;
}

export const updateItem = async (
    userId: string,
    itemId: string,
    updateData: IUpdateItemInput
): Promise<IItem> => {
    const hasEditAccess = await permissionService.hasPermission(
        userId,
        itemId,
        ShareTargetType.ITEM,
        FolderPermissions.EDIT
    );
    if (!hasEditAccess) {
        throw new Error(
            "Forbidden: You do not have permission to edit this item."
        );
    }
    const updatedItem = await Item.findByIdAndUpdate(itemId, updateData, {
        new: true,
    });
    if (!updatedItem) throw new Error("Item not found.");
    return updatedItem;
};

export const deleteItem = async (
    userId: string,
    itemId: string
): Promise<{ message: string }> => {
    const item = await Item.findById(itemId);
    if (!item) throw new Error("Item not found.");
    if (item.ownerId.toString() !== userId) {
        throw new Error("Forbidden: Only the owner can delete this item.");
    }

    await Item.deleteOne({ _id: itemId });
    return { message: "Item deleted successfully" };
};
