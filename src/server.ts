import express, { Application, Request, Response } from "express";
import cors from "cors";
import dotenv from "dotenv";

dotenv.config();

const app: Application = express();
const PORT = process.env.PORT || 5000;

// Middlewares
app.use(cors());
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

app.get("/api/healthcheck", (_req: Request, res: Response) => {
    res.status(200).json({
        status: "OK",
        message: "Lockify backend is up and running!",
        timestamp: new Date().toISOString(),
    });
});

app.listen(PORT, () => {
    console.log(`🚀 Server is running on http://localhost:${PORT}`);
});
