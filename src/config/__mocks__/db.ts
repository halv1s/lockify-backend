import { RedisArgument, SetOptions } from "redis";

const redisStore: { [key: string]: string } = {};

export const redisClient = {
    get: jest.fn((key: string) => Promise.resolve(redisStore[key] || null)),
    set: jest.fn(
        (
            key: RedisArgument,
            value: number | RedisArgument,
            _options?: SetOptions | undefined
        ) => {
            redisStore[key.toString()] = value.toString();
            return Promise.resolve("OK");
        }
    ),
    del: jest.fn((key: string) => {
        delete redisStore[key];
        return Promise.resolve(1);
    }),
};

export const connectDB = jest.fn();

export const connectRedis = jest.fn();
