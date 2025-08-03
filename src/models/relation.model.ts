import mongoose, { Schema, Document } from "mongoose";

import { ReBACRelation } from "@/types";

export interface IRelation extends Document {
    subject: string;
    relation: ReBACRelation;
    object: string;
    encryptedKey?: string;
}

const relationSchema: Schema = new Schema(
    {
        subject: {
            type: String,
            required: true,
            trim: true,
            note: "The subject of the relation. Format: 'users:<user_id>' or a reference to another relation set, e.g., 'workspaces:<workspace_id>#manager'",
        },
        relation: {
            type: String,
            enum: Object.values(ReBACRelation),
            required: true,
            note: "The relation between the subject and object. E.g., 'owner', 'manager', 'editor', 'viewer', 'parent'",
        },
        object: {
            type: String,
            required: true,
            trim: true,
            note: "The object of the relation. Format: 'workspaces:<workspace_id>', 'folders:<folder_id>', 'items:<item_id>'",
        },
        encryptedKey: {
            type: String,
            required: false, // Only required for explicit shares
            note: "Stores the encrypted item/folder key for explicit shares (e.g., for 'editor' or 'viewer' relations)",
        },
    },
    {
        timestamps: true,
    }
);

relationSchema.index({ subject: 1, relation: 1, object: 1 }, { unique: true });

export default mongoose.model<IRelation>("Relation", relationSchema);
