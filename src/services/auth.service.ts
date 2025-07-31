import jwt, { SignOptions } from "jsonwebtoken";
import { randomBytes } from "crypto";
import User, { IUser } from "../models/user.model";
import Workspace from "../models/workspace.model";
import Folder from "../models/folder.model";
import { SRP, SrpServer } from "fast-srp-hap";
import { redisClient } from "../config/db";
import config from "../config";
import mongoose from "mongoose";

interface IRegisterInput {
    email: string;
    srpSalt: string;
    srpVerifier: string;
    rsaPublicKey: string;
}

export const registerUser = async (input: IRegisterInput): Promise<IUser> => {
    const session = await User.startSession();
    session.startTransaction();

    try {
        const existingUser = await User.findOne({ email: input.email }).session(
            session
        );
        if (existingUser) {
            throw new Error("Email already exists");
        }

        const newUser = new User({
            email: input.email,
            srpSalt: input.srpSalt,
            srpVerifier: input.srpVerifier,
            rsaPublicKey: input.rsaPublicKey,
            // We set a temporary value for defaultWorkspaceId that will be updated.
            defaultWorkspaceId: new mongoose.Types.ObjectId(),
        });

        const personalWorkspace = new Workspace({
            ownerId: newUser._id,
            name: "Personal",
        });

        newUser.defaultWorkspaceId =
            personalWorkspace._id as mongoose.Types.ObjectId;

        const defaultFolder = new Folder({
            workspaceId: personalWorkspace._id,
            ownerId: newUser._id,
            name: "Uncategorized",
        });

        await newUser.save({ session });
        await personalWorkspace.save({ session });
        await defaultFolder.save({ session });

        await session.commitTransaction();
        session.endSession();

        return newUser;
    } catch (error: any) {
        await session.abortTransaction();
        session.endSession();
        throw new Error(`Cannot register user: ${error.message}`);
    }
};

export const initiateLogin = async (email: string) => {
    const user = await User.findOne({ email });
    if (!user) {
        throw new Error("User not found.");
    }

    const salt = Buffer.from(user.srpSalt, "hex");
    const verifier = Buffer.from(user.srpVerifier, "hex");
    const secret = await SRP.genKey(32);

    const server = new SrpServer(
        SRP.params[3072],
        {
            username: user.email,
            salt,
            verifier,
        },
        secret
    );

    const serverPublicEphemeral = server.computeB();

    const challengeKey = `srp_challenge:${randomBytes(32).toString("hex")}`;

    await redisClient.set(
        challengeKey,
        JSON.stringify({
            userId: user._id,
            privateKeyB: secret.toString("hex"),
        }),
        { EX: 300 }
    );

    return {
        salt: user.srpSalt,
        serverPublicEphemeral: serverPublicEphemeral.toString("hex"),
        challengeKey,
    };
};

interface IVerifyLoginInput {
    challengeKey: string;
    clientPublicEphemeral: string; // 'A' from the client
    clientProof: string; // 'M1' from the client
}

export const verifyLogin = async (input: IVerifyLoginInput) => {
    const { challengeKey, clientPublicEphemeral, clientProof } = input;

    const cachedData = await redisClient.get(challengeKey);
    if (!cachedData) {
        throw new Error(
            "Invalid or expired login challenge. Please try again."
        );
    }
    await redisClient.del(challengeKey);

    const { privateKeyB: privateKeyBHex, userId } = JSON.parse(cachedData);

    const user = await User.findById(userId);
    if (!user) {
        throw new Error("User associated with this challenge not found.");
    }
    const salt = Buffer.from(user.srpSalt, "hex");
    const verifier = Buffer.from(user.srpVerifier, "hex");

    const privateKeyB = Buffer.from(privateKeyBHex, "hex");
    const server = new SrpServer(
        SRP.params[3072],
        {
            username: user.email,
            salt,
            verifier,
        },
        privateKeyB
    );

    const clientPublicEphemeralBuf = Buffer.from(clientPublicEphemeral, "hex");
    const clientProofBuf = Buffer.from(clientProof, "hex");

    try {
        server.setA(clientPublicEphemeralBuf);
        server.checkM1(clientProofBuf);
    } catch (error) {
        throw new Error("Invalid credentials. Login failed.");
    }

    const sessionToken = jwt.sign(
        { userId: user._id, email: user.email },
        config.jwt.secret,
        { expiresIn: config.jwt.expiresIn as SignOptions["expiresIn"] }
    );

    return {
        token: sessionToken,
        user: {
            id: user.id,
            email: user.email,
        },
    };
};
