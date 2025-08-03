import { Router, Request, Response } from "express";
import { z } from "zod";

import { protect } from "@/middlewares/auth.middleware";
import { validateRequest } from "@/middlewares/validation.middleware";
import * as folderService from "@/services/folder.service";

const router = Router();

const getFoldersSchema = z.object({
    query: z.object({
        workspaceId: z.string({
            message: "workspaceId is required",
        }),
    }),
});

router.get(
    "/",
    protect,
    validateRequest(getFoldersSchema),
    async (req: Request, res: Response) => {
        if (!req.user) {
            return res.status(401).json({ message: "Unauthorized" });
        }

        const { workspaceId } = req.query as { workspaceId: string };

        try {
            const folders = await folderService.getFolders(
                req.user.userId,
                workspaceId
            );
            res.status(200).json({ data: folders });
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

const createFolderSchema = z.object({
    body: z.object({
        name: z.string().min(1, "Folder name is required"),
        workspaceId: z.string().min(1, "workspaceId is required"),
        parentId: z.string().optional(),
    }),
});

router.post(
    "/",
    protect,
    validateRequest(createFolderSchema),
    async (req: Request, res: Response) => {
        if (!req.user) {
            return res.status(401).json({ message: "Unauthorized" });
        }

        const { name, workspaceId, parentId } = req.body;

        try {
            const newFolder = await folderService.createFolder(
                req.user.userId,
                workspaceId,
                name,
                parentId
            );
            res.status(201).json({ data: newFolder });
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
