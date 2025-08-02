import type { Config } from "jest";

const config: Config = {
    preset: "ts-jest",
    testEnvironment: "node",
    setupFilesAfterEnv: ["<rootDir>/src/test/setup.ts"],
    clearMocks: true,
    coverageDirectory: "coverage/e2e",
    moduleNameMapper: {
        "^@/(.*)$": "<rootDir>/src/$1",
    },
    testMatch: ["<rootDir>/src/**/*.e2e.test.ts"],
    testTimeout: 30000,
};

export default config;
