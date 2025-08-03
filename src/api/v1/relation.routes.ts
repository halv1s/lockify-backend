import { Router, Request, Response } from "express";

import { protect } from "@/middlewares/auth.middleware";
import * as relationService from "@/services/relation.service";
import { ReBACNamespace, ReBACRelation } from "@/types";

const router = Router();

router.post("/", protect, async (req: Request, res: Response) => {
    if (!req.user) {
        return res.status(401).json({ message: "Unauthorized" });
    }

    const { recipientEmail, targetId, targetType, permissions, encryptedKey } =
        req.body;

    if (
        !recipientEmail ||
        !targetId ||
        !targetType ||
        !permissions ||
        !encryptedKey
    ) {
        return res
            .status(400)
            .json({ message: "Missing required fields for sharing." });
    }

    const permissionToGrant = permissions as ReBACRelation;
    const targetNamespace = targetType as ReBACNamespace;

    if (
        permissionToGrant !== ReBACRelation.EDITOR &&
        permissionToGrant !== ReBACRelation.VIEWER
    ) {
        return res
            .status(400)
            .json({ message: "Invalid permission type for sharing." });
    }

    try {
        const newRelation = await relationService.shareResource({
            initiatorId: req.user.userId,
            recipientEmail,
            targetId,
            targetNamespace,
            permissionToGrant,
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
            errorMessage.includes("You cannot share a resource with yourself")
        ) {
            return res.status(400).json({ message: errorMessage });
        }

        res.status(500).json({ message: "Server error", error: errorMessage });
    }
});

export default router;
