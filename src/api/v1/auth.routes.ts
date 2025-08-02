import { Router, Request, Response } from "express";

import * as authService from "@/services/auth.service";

const router = Router();

router.post("/register", async (req: Request, res: Response) => {
    const { email, masterSalt, srpSalt, srpVerifier, rsaPublicKey } = req.body;

    if (!email || !masterSalt || !srpSalt || !srpVerifier || !rsaPublicKey) {
        return res
            .status(400)
            .json({ message: "Please provide all information." });
    }

    try {
        const newUser = await authService.registerUser({
            email,
            masterSalt,
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
    } catch (error: unknown) {
        if (
            error instanceof Error &&
            error.message.includes("Email already exists")
        ) {
            return res.status(409).json({ message: error.message });
        }
        res.status(500).json({
            message: "Internal server error.",
            error: error instanceof Error ? error.message : "Unknown error",
        });
    }
});

router.post("/login/initiate", async (req: Request, res: Response) => {
    try {
        const { email } = req.body;
        if (!email) {
            return res.status(400).json({ message: "Email is required." });
        }
        const result = await authService.initiateLogin(email);
        res.status(200).json(result);
    } catch {
        res.status(404).json({ message: "Invalid credentials." });
    }
});

router.post("/login/verify", async (req: Request, res: Response) => {
    try {
        const { challengeKey, clientPublicEphemeral, clientProof } = req.body;

        if (!challengeKey || !clientPublicEphemeral || !clientProof) {
            return res
                .status(400)
                .json({ message: "Please provide all information." });
        }

        const result = await authService.verifyLogin({
            challengeKey,
            clientPublicEphemeral,
            clientProof,
        });

        res.status(200).json(result);
    } catch (error: unknown) {
        res.status(401).json({
            message:
                error instanceof Error ? error.message : "Invalid credentials.",
        });
    }
});

export default router;
