import dotenv from "dotenv";

dotenv.config();

const MONGO_URI = process.env.MONGO_URI;
const REDIS_URL = process.env.REDIS_URL;

if (!MONGO_URI || !REDIS_URL) {
    console.error("Error: Please provide MONGO_URI and REDIS_URL in .env file");
    process.exit(1);
}

const config = {
    port: process.env.PORT || 5000,
    mongoUri: MONGO_URI,
    redisUrl: process.env.REDIS_URL,
    jwt: {
        secret: process.env.JWT_SECRET || "your-default-secret",
        expiresIn: process.env.JWT_EXPIRES_IN || "1h",
    },
};

export default config;
