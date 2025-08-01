import { Request, Response, NextFunction } from "express";
import jwt from "jsonwebtoken";

import config from "@/config";

export const protect = (req: Request, res: Response, next: NextFunction) => {
    const bearer = req.headers.authorization;

    if (!bearer || !bearer.startsWith("Bearer ")) {
        return res
            .status(401)
            .json({ message: "Unauthorized: No token provided" });
    }

    const token = bearer.split(" ")[1].trim();
    if (!token) {
        return res
            .status(401)
            .json({ message: "Unauthorized: Malformed token" });
    }

    try {
        const user = jwt.verify(token, config.jwt.secret) as {
            userId: string;
            email: string;
            iat: number;
            exp: number;
        };

        req.user = {
            userId: user.userId,
            email: user.email,
        };

        next();
    } catch (error) {
        console.error("Token verification error:", error);
        return res.status(401).json({ message: "Unauthorized: Invalid token" });
    }
};
