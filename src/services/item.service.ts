import mongoose from "mongoose";

import Item, { IItem } from "@/models/item.model";
import Relation from "@/models/relation.model";
import { hasPermission } from "@/services/permission.service";
import { ItemType, ReBACNamespace, ReBACRelation } from "@/types";

export const getItemsInFolder = async (userId: string, folderId: string) => {
    const canViewFolder = await hasPermission(
        userId,
        ReBACRelation.VIEWER,
        ReBACNamespace.FOLDERS,
        folderId
    );

    if (!canViewFolder) {
        throw new Error(
            "Forbidden: You do not have permission to view items in this folder."
        );
    }

    const items = await Item.find({
        folderId: new mongoose.Types.ObjectId(folderId),
    }).select(
        "-encryptedData -encryptedDataIv -encryptedRecordKey -encryptedRecordKeyIv"
    );

    return items;
};

export const getItemById = async (
    userId: string,
    itemId: string
): Promise<IItem> => {
    const canReadItem = await hasPermission(
        userId,
        ReBACRelation.VIEWER,
        ReBACNamespace.ITEMS,
        itemId
    );

    if (!canReadItem) {
        throw new Error(
            "Forbidden: You do not have permission to access this item."
        );
    }
    const item = await Item.findById(itemId);
    if (!item) throw new Error("Item not found.");
    return item;
};

interface ICreateItemInput {
    creatorId: string;
    folderId: string;
    type: ItemType;
    displayMetadata?: object;
    encryptedData: string;
    encryptedDataIv: string;
    encryptedRecordKey: string;
    encryptedRecordKeyIv: string;
}

export const createItem = async (input: ICreateItemInput): Promise<IItem> => {
    const { creatorId, folderId, ...itemData } = input;

    const canCreateInFolder = await hasPermission(
        creatorId,
        ReBACRelation.EDITOR,
        ReBACNamespace.FOLDERS,
        folderId
    );

    if (!canCreateInFolder) {
        throw new Error(
            "Forbidden: You do not have permission to create items in this folder."
        );
    }

    const session = await mongoose.startSession();
    session.startTransaction();

    try {
        const newItem = new Item({
            folderId,
            ...itemData,
        });
        await newItem.save({ session });

        const userSubject = `${ReBACNamespace.USERS}:${creatorId}`;
        const itemObject = `${ReBACNamespace.ITEMS}:${newItem._id}`;
        const folderObject = `${ReBACNamespace.FOLDERS}:${folderId}`;

        const relationsToCreate = [
            {
                subject: userSubject,
                relation: ReBACRelation.OWNER,
                object: itemObject,
            },
            {
                subject: itemObject,
                relation: ReBACRelation.PARENT,
                object: folderObject,
            },
        ];

        await Relation.insertMany(relationsToCreate, { session });

        await session.commitTransaction();
        session.endSession();
        return newItem;
    } catch (error) {
        await session.abortTransaction();
        session.endSession();
        throw error;
    }
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
    const canEditItem = await hasPermission(
        userId,
        ReBACRelation.EDITOR,
        ReBACNamespace.ITEMS,
        itemId
    );
    if (!canEditItem) {
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
    const canDeleteItem = await hasPermission(
        userId,
        ReBACRelation.EDITOR,
        ReBACNamespace.ITEMS,
        itemId
    );

    if (!canDeleteItem) {
        throw new Error(
            "Forbidden: You do not have permission to delete this item."
        );
    }

    const session = await mongoose.startSession();
    session.startTransaction();
    try {
        const deletedItem = await Item.findByIdAndDelete(itemId, { session });
        if (!deletedItem) throw new Error("Item not found.");

        // Clean up all relations associated with the deleted item.
        const itemObject = `${ReBACNamespace.ITEMS}:${itemId}`;
        await Relation.deleteMany(
            { $or: [{ subject: itemObject }, { object: itemObject }] },
            { session }
        );

        await session.commitTransaction();
        session.endSession();
        return { message: "Item deleted successfully" };
    } catch (error) {
        await session.abortTransaction();
        session.endSession();
        throw error;
    }
};
