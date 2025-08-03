import { Router, Request, Response } from "express";
import { z } from "zod";

import { protect } from "@/middlewares/auth.middleware";
import {
    mongoIdSchema,
    validateRequest,
} from "@/middlewares/validation.middleware";
import * as itemService from "@/services/item.service";
import { ItemType } from "@/types";

const router = Router();

const getItemsSchema = z.object({
    query: z.object({
        folderId: mongoIdSchema,
    }),
});

router.get(
    "/",
    protect,
    validateRequest(getItemsSchema),
    async (req: Request, res: Response) => {
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
            res.status(500).json({
                message: "Server error",
                error: errorMessage,
            });
        }
    }
);

const getItemSchema = z.object({
    params: z.object({
        itemId: mongoIdSchema,
    }),
});

router.get(
    "/:itemId",
    protect,
    validateRequest(getItemSchema),
    async (req: Request, res: Response) => {
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

            res.status(500).json({
                message: "Server error",
                error: errorMessage,
            });
        }
    }
);

const createItemSchema = z.object({
    body: z.object({
        folderId: mongoIdSchema,
        type: z.enum(ItemType),
        displayMetadata: z.looseObject({}).optional(),
        encryptedData: z.string().min(1),
        encryptedDataIv: z.string().min(1),
        encryptedRecordKey: z.string().min(1),
        encryptedRecordKeyIv: z.string().min(1),
    }),
});

router.post(
    "/",
    protect,
    validateRequest(createItemSchema),
    async (req: Request, res: Response) => {
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
            res.status(500).json({
                message: "Server error",
                error: errorMessage,
            });
        }
    }
);

const updateItemSchema = z.object({
    params: z.object({
        itemId: mongoIdSchema,
    }),
    body: z.object({
        displayMetadata: z.looseObject({}).optional(),
        encryptedData: z.string().min(1).optional(),
        encryptedDataIv: z.string().min(1).optional(),
    }),
});

router.put(
    "/:itemId",
    protect,
    validateRequest(updateItemSchema),
    async (req: Request, res: Response) => {
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
            res.status(500).json({
                message: "Server error",
                error: errorMessage,
            });
        }
    }
);

const deleteItemSchema = z.object({
    params: z.object({
        itemId: mongoIdSchema,
    }),
});

router.delete(
    "/:itemId",
    protect,
    validateRequest(deleteItemSchema),
    async (req: Request, res: Response) => {
        if (!req.user) {
            return res.status(401).json({ message: "Unauthorized" });
        }
        const { itemId } = req.params;

        try {
            const result = await itemService.deleteItem(
                req.user.userId,
                itemId
            );
            res.status(200).json(result);
        } catch (error: unknown) {
            const errorMessage =
                error instanceof Error ? error.message : "Unknown error";
            if (errorMessage.includes("Forbidden")) {
                return res.status(403).json({ message: errorMessage });
            }
            res.status(500).json({
                message: "Server error",
                error: errorMessage,
            });
        }
    }
);

export default router;
