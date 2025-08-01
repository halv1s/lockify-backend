import { Router, Request, Response } from "express";

import { protect } from "@/middlewares/auth.middleware";
import * as folderService from "@/services/folder.service";

const router = Router();

router.get("/", protect, async (req: Request, res: Response) => {
    if (!req.user) {
        return res.status(401).json({ message: "Unauthorized" });
    }

    const { workspaceId } = req.query;

    if (!workspaceId) {
        return res.status(400).json({ message: "workspaceId is required" });
    }

    try {
        const folders = await folderService.getFolders(
            req.user.userId,
            workspaceId as string
        );
        res.status(200).json({ data: folders });
    } catch (error: unknown) {
        const errorMessage =
            error instanceof Error ? error.message : "Unknown error";

        if (errorMessage.includes("Forbidden")) {
            return res.status(403).json({ message: errorMessage });
        }

        res.status(500).json({ message: "Server error", error: errorMessage });
    }
});

router.post("/", protect, async (req: Request, res: Response) => {
    if (!req.user) {
        return res.status(401).json({ message: "Unauthorized" });
    }

    const { name, workspaceId, parentId } = req.body;

    if (!name || !workspaceId) {
        return res
            .status(400)
            .json({ message: "Folder name and workspaceId are required" });
    }

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

        res.status(500).json({ message: "Server error", error: errorMessage });
    }
});

export default router;
