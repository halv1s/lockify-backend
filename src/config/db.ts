import mongoose from "mongoose";
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
