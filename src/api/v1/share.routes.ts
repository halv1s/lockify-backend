import { Router, Request, Response } from "express";

import { protect } from "@/middlewares/auth.middleware";
import * as shareService from "@/services/share.service";
import { FolderPermissions, ShareTargetType } from "@/types";

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

    try {
        const newShare = await shareService.shareResource({
            initiatorId: req.user.userId,
            recipientEmail,
            targetId,
            targetType: targetType as ShareTargetType,
            permissions: permissions as FolderPermissions,
            encryptedKey,
        });
        res.status(201).json({ data: newShare });
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
