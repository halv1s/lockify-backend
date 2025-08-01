import cors from "cors";
import dotenv from "dotenv";
import express, { Application, Request, Response } from "express";

import authRoutes from "./api/v1/auth.routes";
import folderRoutes from "./api/v1/folder.routes";
import workspaceRoutes from "./api/v1/workspace.routes";
import { connectDB, connectRedis } from "./config/db";

dotenv.config();

const app: Application = express();
const PORT = process.env.PORT || 5000;

// Middlewares
app.use(cors());
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

app.use("/api/v1/auth", authRoutes);
app.use("/api/v1/folders", folderRoutes);
app.use("/api/v1/workspaces", workspaceRoutes);

app.get("/api/healthcheck", (_req: Request, res: Response) => {
    res.status(200).json({
        status: "OK",
        message: "Lockify backend is up and running!",
        timestamp: new Date().toISOString(),
    });
});

if (process.env.NODE_ENV !== "test") {
    const startServer = async () => {
        await connectDB();
        await connectRedis();

        app.listen(PORT, () => {
            console.log(`🚀 Server is running on http://localhost:${PORT}`);
        });
    };

    startServer();
}

export default app;
