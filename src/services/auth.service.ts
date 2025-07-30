import User, { IUser } from "../models/user.model";

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
