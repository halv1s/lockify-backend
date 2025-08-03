import { Router, Request, Response } from "express";
import { z } from "zod";

import { protect } from "@/middlewares/auth.middleware";
import { validateRequest } from "@/middlewares/validation.middleware";
import * as relationService from "@/services/relation.service";
import { ReBACNamespace, ReBACRelation } from "@/types";

const router = Router();

const createRelationSchema = z.object({
    body: z.object({
        recipientEmail: z.email("Invalid recipient email format"),
        targetId: z.string().min(1, "targetId is required"),
        targetType: z.enum(ReBACNamespace, { error: "Invalid targetType" }),
        permissions: z.enum([ReBACRelation.EDITOR, ReBACRelation.VIEWER], {
            error: "Permissions must be either 'editor' or 'viewer'",
        }),
        encryptedKey: z.string().min(1, "encryptedKey is required"),
    }),
});

router.post(
    "/",
    protect,
    validateRequest(createRelationSchema),
    async (req: Request, res: Response) => {
        if (!req.user) {
            return res.status(401).json({ message: "Unauthorized" });
        }

        const {
            recipientEmail,
            targetId,
            targetType,
            permissions,
            encryptedKey,
        } = req.body;

        try {
            const newRelation = await relationService.shareResource({
                initiatorId: req.user.userId,
                recipientEmail,
                targetId,
                targetNamespace: targetType,
                permissionToGrant: permissions,
                encryptedKey,
            });
            res.status(201).json({ data: newRelation });
        } catch (error: unknown) {
            const errorMessage =
                error instanceof Error ? error.message : "Unknown error";

            if (errorMessage.includes("Forbidden")) {
                return res.status(403).json({ message: errorMessage });
            }
            if (errorMessage.includes("not found")) {
                return res.status(404).json({ message: errorMessage });
            }
            if (
                errorMessage.includes(
                    "You cannot share a resource with yourself"
                )
            ) {
                return res.status(400).json({ message: errorMessage });
            }

            res.status(500).json({
                message: "Server error",
                error: errorMessage,
            });
        }
    }
);

export default router;
