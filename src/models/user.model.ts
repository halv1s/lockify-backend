import mongoose, { Schema, Document } from "mongoose";

export interface IUser extends Document {
    email: string;
    srpSalt: string;
    srpVerifier: string;
    rsaPublicKey: string;
    hasPaid: boolean;
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
        hasPaid: {
            type: Boolean,
            default: false,
        },
    },
    {
        timestamps: true,
    }
);

export default mongoose.model<IUser>("User", userSchema);
