import mongoose from "mongoose";
import { createClient } from "redis";

import config from "./index";

export const connectDB = async () => {
    try {
        await mongoose.connect(config.mongoUri);
        console.log("✅ MongoDB connected");
    } catch (error) {
        console.error("❌ Could not connect to MongoDB:", error);
        process.exit(1);
    }
};

export const redisClient = createClient({ url: config.redisUrl });

export const connectRedis = async () => {
    try {
        await redisClient.connect();
        console.log("✅ Redis connected");
    } catch (error) {
        console.error("❌ Could not connect to Redis:", error);
        process.exit(1);
    }
};
