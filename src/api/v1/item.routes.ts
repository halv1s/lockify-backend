import { Router, Request, Response } from "express";

import { protect } from "@/middlewares/auth.middleware";
import * as itemService from "@/services/item.service";
import { ItemType } from "@/types";

const router = Router();

router.get("/", protect, async (req: Request, res: Response) => {
    if (!req.user) {
        return res.status(401).json({ message: "Unauthorized" });
    }

    const { folderId } = req.query;

    if (!folderId) {
        return res
            .status(400)
            .json({ message: "A folderId query parameter is required" });
    }

    try {
        const items = await itemService.getItemsInFolder(
            req.user.userId,
            folderId as string
        );
        res.status(200).json({ data: items });
    } catch (error: unknown) {
        const errorMessage =
            error instanceof Error ? error.message : "Unknown error";
        if (errorMessage.includes("Forbidden")) {
            return res.status(403).json({ message: errorMessage });
        }
        res.status(500).json({ message: "Server error", error: errorMessage });
    }
});

router.get("/:itemId", protect, async (req: Request, res: Response) => {
    if (!req.user) {
        return res.status(401).json({ message: "Unauthorized" });
    }

    const { itemId } = req.params;

    try {
        const item = await itemService.getItemById(req.user.userId, itemId);
        res.status(200).json({ data: item });
    } catch (error: unknown) {
        const errorMessage =
            error instanceof Error ? error.message : "Unknown error";

        if (errorMessage.includes("Forbidden")) {
            return res.status(403).json({ message: errorMessage });
        }
        if (errorMessage.includes("not found")) {
            return res.status(404).json({ message: errorMessage });
        }

        res.status(500).json({ message: "Server error", error: errorMessage });
    }
});

router.post("/", protect, async (req: Request, res: Response) => {
    if (!req.user) {
        return res.status(401).json({ message: "Unauthorized" });
    }

    const {
        folderId,
        type,
        displayMetadata,
        encryptedData,
        encryptedDataIv,
        encryptedRecordKey,
        encryptedRecordKeyIv,
    } = req.body;

    if (!folderId || !type || !encryptedData || !encryptedRecordKey) {
        return res.status(400).json({
            message:
                "folderId, type, encryptedData, and encryptedRecordKey are required",
        });
    }

    try {
        const newItem = await itemService.createItem({
            creatorId: req.user.userId,
            folderId,
            type: type as ItemType,
            displayMetadata,
            encryptedData,
            encryptedDataIv,
            encryptedRecordKey,
            encryptedRecordKeyIv,
        });
        res.status(201).json({ data: newItem });
    } catch (error: unknown) {
        const errorMessage =
            error instanceof Error ? error.message : "Unknown error";
        if (errorMessage.includes("Forbidden")) {
            return res.status(403).json({ message: errorMessage });
        }
        res.status(500).json({ message: "Server error", error: errorMessage });
    }
});

router.put("/:itemId", protect, async (req: Request, res: Response) => {
    if (!req.user) {
        return res.status(401).json({ message: "Unauthorized" });
    }
    const { itemId } = req.params;
    const updateData = req.body;

    try {
        const updatedItem = await itemService.updateItem(
            req.user.userId,
            itemId,
            updateData
        );
        res.status(200).json({ data: updatedItem });
    } catch (error: unknown) {
        const errorMessage =
            error instanceof Error ? error.message : "Unknown error";
        if (errorMessage.includes("Forbidden")) {
            return res.status(403).json({ message: errorMessage });
        }
        res.status(500).json({ message: "Server error", error: errorMessage });
    }
});

router.delete("/:itemId", protect, async (req: Request, res: Response) => {
    if (!req.user) {
        return res.status(401).json({ message: "Unauthorized" });
    }
    const { itemId } = req.params;

    try {
        const result = await itemService.deleteItem(req.user.userId, itemId);
        res.status(200).json(result);
    } catch (error: unknown) {
        const errorMessage =
            error instanceof Error ? error.message : "Unknown error";
        if (errorMessage.includes("Forbidden")) {
            return res.status(403).json({ message: errorMessage });
        }
        res.status(500).json({ message: "Server error", error: errorMessage });
    }
});

export default router;
