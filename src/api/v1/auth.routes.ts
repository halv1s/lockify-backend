import { Router, Request, Response } from "express";
import * as authService from "../../services/auth.service";

const router = Router();

router.post("/register", async (req: Request, res: Response) => {
    const { email, srpSalt, srpVerifier, rsaPublicKey } = req.body;

    if (!email || !srpSalt || !srpVerifier || !rsaPublicKey) {
        return res
            .status(400)
            .json({ message: "Please provide all information." });
    }

    try {
        const newUser = await authService.registerUser({
            email,
            srpSalt,
            srpVerifier,
            rsaPublicKey,
        });

        res.status(201).json({
            message: "Register successfully!",
            user: {
                id: newUser._id,
                email: newUser.email,
            },
        });
    } catch (error: any) {
        if (error.message.includes("Email already exists")) {
            return res.status(409).json({ message: error.message });
        }
        res.status(500).json({
            message: "Internal server error.",
            error: error.message,
        });
    }
});

export default router;
