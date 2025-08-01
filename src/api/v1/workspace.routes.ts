import { Router, Request, Response } from "express";

import { protect } from "@/middlewares/auth.middleware";
import * as workspaceService from "@/services/workspace.service"; // highlight-line

const router = Router();

router.get("/", protect, async (req: Request, res: Response) => {
    if (!req.user) {
        return res.status(401).json({ message: "Unauthorized" });
    }

    try {
        const workspaces = await workspaceService.getWorkspacesForUser(
            req.user.userId
        );
        res.status(200).json({ data: workspaces });
    } catch (error: unknown) {
        const errorMessage =
            error instanceof Error ? error.message : "Unknown error";
        res.status(500).json({ message: "Server error", error: errorMessage });
    }
});

router.post("/", protect, async (req: Request, res: Response) => {
    if (!req.user) {
        return res.status(401).json({ message: "Unauthorized" });
    }

    const { name } = req.body;

    if (!name) {
        return res.status(400).json({ message: "Workspace name is required" });
    }

    try {
        const newWorkspace = await workspaceService.createWorkspace(
            req.user.userId,
            name
        );
        res.status(201).json({ data: newWorkspace });
    } catch (error: unknown) {
        const errorMessage =
            error instanceof Error ? error.message : "Unknown error";
        res.status(500).json({ message: "Server error", error: errorMessage });
    }
});

export default router;
