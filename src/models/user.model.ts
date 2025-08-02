import mongoose, { Schema, Document } from "mongoose";

export interface IUser extends Document {
    email: string;
    masterSalt: string;
    srpSalt: string;
    srpVerifier: string;
    rsaPublicKey: string;
    defaultWorkspaceId: mongoose.Types.ObjectId;
}

const userSchema: Schema = new Schema(
    {
        email: {
            type: String,
            required: [true, "Email is required"],
            unique: true,
            trim: true,
            lowercase: true,
            match: [/\S+@\S+\.\S+/, "Email is not valid"],
        },
        masterSalt: {
            type: String,
            required: true,
        },
        srpSalt: {
            type: String,
            required: true,
        },
        srpVerifier: {
            type: String,
            required: true,
        },
        rsaPublicKey: {
            type: String,
            required: true,
        },
        defaultWorkspaceId: {
            type: Schema.Types.ObjectId,
            ref: "Workspace",
            required: true,
        },
    },
    {
        timestamps: true,
    }
);

export default mongoose.model<IUser>("User", userSchema);
