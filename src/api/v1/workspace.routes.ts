import { Router, Request, Response } from "express";
import { protect } from "../../middlewares/auth.middleware";

const router = Router();

router.get("/", protect, async (req: Request, res: Response) => {
    if (!req.user) {
        return res.status(401).json({ message: "Unauthorized" });
    }

    try {
        throw new Error("Not implemented");
    } catch (error) {
        res.status(500).json({ message: "Server error" });
    }
});

export default router;
