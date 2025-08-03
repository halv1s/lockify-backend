import { Router, Request, Response } from "express";
import { z } from "zod";

import { protect } from "@/middlewares/auth.middleware";
import { validateRequest } from "@/middlewares/validation.middleware";
import * as workspaceService from "@/services/workspace.service";

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

const createWorkspaceSchema = z.object({
    body: z.object({
        name: z
            .string({ error: "Workspace name is required" })
            .min(1, "Workspace name cannot be empty"),
    }),
});

router.post(
    "/",
    protect,
    validateRequest(createWorkspaceSchema),
    async (req: Request, res: Response) => {
        if (!req.user) {
            return res.status(401).json({ message: "Unauthorized" });
        }

        try {
            const newWorkspace = await workspaceService.createWorkspace(
                req.user.userId,
                req.body.name
            );
            res.status(201).json({ data: newWorkspace });
        } catch (error: unknown) {
            const errorMessage =
                error instanceof Error ? error.message : "Unknown error";
            res.status(500).json({
                message: "Server error",
                error: errorMessage,
            });
        }
    }
);

export default router;
