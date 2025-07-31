import { MongoMemoryReplSet } from "mongodb-memory-server";
import mongoose from "mongoose";

let mongo: MongoMemoryReplSet;

beforeAll(async () => {
    mongo = await MongoMemoryReplSet.create({ replSet: { count: 3 } });
    const mongoUri = mongo.getUri();
    await mongoose.connect(mongoUri);
});

beforeEach(async () => {
    if (!mongoose.connection.db) {
        throw new Error("MongoDB connection not established");
    }
    await mongoose.connection.db.dropDatabase();
});

afterAll(async () => {
    await mongoose.connection.close();
    await mongo.stop();
});
