import { MongoMemoryReplSet } from "mongodb-memory-server";
import mongoose from "mongoose";

// https://github.com/typegoose/mongodb-memory-server/blob/master/packages/mongodb-memory-server-core/src/__tests__/replset-multi.test.ts
let replset: MongoMemoryReplSet;

beforeAll(async () => {
    replset = await MongoMemoryReplSet.create({ replSet: { count: 3 } });
    const mongoUri = replset.getUri();
    await mongoose.connect(mongoUri);
    // await while all SECONDARIES will be ready
    await new Promise((resolve) => setTimeout(resolve, 1000));
});

beforeEach(async () => {
    if (!mongoose.connection.db) {
        throw new Error("MongoDB connection not established");
    }
    await mongoose.connection.db.dropDatabase();
});

afterAll(async () => {
    await mongoose.connection.close();
    // https://github.com/typegoose/mongodb-memory-server/issues/228
    await replset.stop();
});
