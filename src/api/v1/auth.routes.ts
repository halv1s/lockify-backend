import { Router, Request, Response } from "express";
import { z } from "zod";

import { validateRequest } from "@/middlewares/validation.middleware";
import * as authService from "@/services/auth.service";

const router = Router();

const registerSchema = z.object({
    body: z.object({
        email: z.email("Email is not valid"),
        masterSalt: z.string().min(1, "masterSalt is required"),
        srpSalt: z.string().min(1, "srpSalt is required"),
        srpVerifier: z.string().min(1, "srpVerifier is required"),
        rsaPublicKey: z.string().min(1, "rsaPublicKey is required"),
        encryptedRsaPrivateKey: z
            .string()
            .min(1, "encryptedRsaPrivateKey is required"),
        encryptedRsaPrivateKeyIv: z
            .string()
            .min(1, "encryptedRsaPrivateKeyIv is required"),
    }),
});

router.post(
    "/register",
    validateRequest(registerSchema),
    async (req: Request, res: Response) => {
        try {
            const newUser = await authService.registerUser(req.body);

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
    }
);

const loginInitiateSchema = z.object({
    body: z.object({
        email: z.email("A valid email is required."),
    }),
});

router.post(
    "/login/initiate",
    validateRequest(loginInitiateSchema),
    async (req: Request, res: Response) => {
        try {
            const result = await authService.initiateLogin(req.body.email);
            res.status(200).json(result);
        } catch {
            res.status(404).json({ message: "Invalid credentials." });
        }
    }
);

const loginVerifySchema = z.object({
    body: z.object({
        challengeKey: z.string().min(1, "challengeKey is required"),
        clientPublicEphemeral: z
            .string()
            .min(1, "clientPublicEphemeral is required"),
        clientProof: z.string().min(1, "clientProof is required"),
    }),
});

router.post(
    "/login/verify",
    validateRequest(loginVerifySchema),
    async (req: Request, res: Response) => {
        try {
            const result = await authService.verifyLogin(req.body);
            res.status(200).json(result);
        } catch (error: unknown) {
            res.status(401).json({
                message:
                    error instanceof Error
                        ? error.message
                        : "Invalid credentials.",
            });
        }
    }
);

export default router;
