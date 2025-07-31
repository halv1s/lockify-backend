import jwt from "jsonwebtoken";
import { randomBytes } from "crypto";
import User, { IUser } from "../models/user.model";
import { SRP, SrpServer } from "fast-srp-hap";
import { redisClient } from "../config/db";
import config from "../config";

interface IRegisterInput {
    email: string;
    srpSalt: string;
    srpVerifier: string;
    rsaPublicKey: string;
}

export const registerUser = async (input: IRegisterInput): Promise<IUser> => {
    try {
        const existingUser = await User.findOne({ email: input.email });
        if (existingUser) {
            throw new Error("Email already exists");
        }

        const newUser = new User({
            email: input.email,
            srpSalt: input.srpSalt,
            srpVerifier: input.srpVerifier,
            rsaPublicKey: input.rsaPublicKey,
        });

        await newUser.save();

        return newUser;
    } catch (error: any) {
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

    const sessionToken = jwt.sign({ userId: user._id }, config.jwt.secret, {
        expiresIn: "1h",
    });

    return {
        token: sessionToken,
        user: {
            id: user.id,
            email: user.email,
        },
    };
};
