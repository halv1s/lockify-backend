import dotenv from "dotenv";

dotenv.config();

const MONGO_URI = process.env.MONGO_URI;

if (!MONGO_URI) {
    console.error("Error: Please provide MONGO_URI in .env file");
    process.exit(1);
}

const config = {
    port: process.env.PORT || 5000,
    mongoUri: MONGO_URI,
    jwt: {
        secret: process.env.JWT_SECRET || "your-default-secret",
        expiresIn: process.env.JWT_EXPIRES_IN || "1d",
    },
};

export default config;
