import mongoose, { Schema, Document } from "mongoose";

import { ItemType } from "../types";

export interface IItem extends Document {
    folderId: mongoose.Types.ObjectId;
    ownerId: mongoose.Types.ObjectId;
    type: ItemType;
    displayMetadata?: object;
    encryptedData: string;
    encryptedRecordKey: string;
}

const itemSchema: Schema = new Schema(
    {
        folderId: {
            type: Schema.Types.ObjectId,
            ref: "Folder",
            required: true,
        },
        ownerId: {
            type: Schema.Types.ObjectId,
            ref: "User",
            required: true,
        },
        type: {
            type: String,
            enum: Object.values(ItemType),
            required: true,
        },
        // For non-sensitive UI data like title, icon url, etc.
        displayMetadata: {
            type: Schema.Types.Mixed,
            required: false,
        },
        // A single encrypted blob containing a JSON object with all fields
        encryptedData: {
            type: String,
            required: true,
        },
        // The key for this specific item
        encryptedRecordKey: {
            type: String,
            required: true,
        },
    },
    {
        timestamps: true,
    }
);

export default mongoose.model<IItem>("Item", itemSchema);
