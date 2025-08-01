import { MongoMemoryReplSet } from "mongodb-memory-server";
import mongoose from "mongoose";

// https://github.com/typegoose/mongodb-memory-server/blob/master/packages/mongodb-memory-server-core/src/__tests__/replset-multi.test.ts
let replset: MongoMemoryReplSet;

beforeAll(async () => {
    replset = await MongoMemoryReplSet.create({ replSet: { count: 1 } });

    const mongoUri = replset.getUri();
    await mongoose.connect(mongoUri);

    await new Promise((resolve) => setTimeout(resolve, 2000));

    if (mongoose.connection.db) {
        await mongoose.connection.db.admin().ping();
    }
});

beforeEach(async () => {
    if (!mongoose.connection.db) {
        throw new Error("MongoDB connection not established");
    }

    const collections = await mongoose.connection.db.collections();
    for (const collection of collections) {
        await collection.deleteMany({});
    }
});

afterAll(async () => {
    await mongoose.connection.close();
    // https://github.com/typegoose/mongodb-memory-server/issues/228
    await replset.stop();
});
