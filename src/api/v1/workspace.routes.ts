import { Router, Request, Response } from "express";
import { protect } from "../../middlewares/auth.middleware";
import * as workspaceService from "../../services/workspace.service"; // highlight-line

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
    } catch (error: any) {
        res.status(500).json({ message: "Server error", error: error.message });
    }
});

export default router;
