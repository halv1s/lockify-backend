import { SRP, SrpClient } from "fast-srp-hap";
import request from "supertest";

import Folder from "@/models/folder.model";
import User from "@/models/user.model";
import Workspace from "@/models/workspace.model";
import app from "@/server";

jest.mock("@/config/db");

describe("Auth Routes /api/v1/auth", () => {
    describe("POST /register", () => {
        const testUser = {
            email: "test@example.com",
            masterSalt: "somemastersalt",
            srpSalt: "somesalt",
            srpVerifier: "someverifier",
            rsaPublicKey: "somekey",
        };

        it("should register a new user and create a default workspace and folder", async () => {
            const res = await request(app)
                .post("/api/v1/auth/register")
                .send(testUser);

            expect(res.status).toBe(201);
            expect(res.body.user).toHaveProperty("email", testUser.email);

            const user = await User.findOne({ email: testUser.email });
            expect(user).not.toBeNull();
            expect(user!.masterSalt).toBe(testUser.masterSalt);
            expect(user!.srpSalt).toBe(testUser.srpSalt);
            expect(user!.srpVerifier).toBe(testUser.srpVerifier);
            expect(user!.rsaPublicKey).toBe(testUser.rsaPublicKey);

            const workspace = await Workspace.findById(
                user!.defaultWorkspaceId
            );
            expect(workspace).not.toBeNull();
            expect(workspace!.name).toBe("Personal");

            const folder = await Folder.findOne({
                workspaceId: workspace!._id,
            });
            expect(folder).not.toBeNull();
            expect(folder!.name).toBe("Uncategorized");
        });

        it("should fail with status 409 if email already exists", async () => {
            await request(app).post("/api/v1/auth/register").send(testUser);

            const res = await request(app)
                .post("/api/v1/auth/register")
                .send(testUser);

            expect(res.status).toBe(409);
            expect(res.body).toHaveProperty(
                "message",
                "Cannot register user: Email already exists"
            );
        });

        it("should fail with status 400 if required fields are missing", async () => {
            const res = await request(app)
                .post("/api/v1/auth/register")
                .send({ email: "test@example.com" });

            expect(res.status).toBe(400);
            expect(res.body).toHaveProperty(
                "message",
                "Please provide all information."
            );
        });
    });

    describe("Login Flow", () => {
        const identity = "login-test@example.com";
        const password = "a-very-secure-password";
        let salt: Buffer;
        let verifier: Buffer;

        beforeEach(async () => {
            salt = await SRP.genKey(32);
            verifier = SRP.computeVerifier(
                SRP.params[3072],
                salt,
                Buffer.from(identity),
                Buffer.from(password)
            );

            await request(app)
                .post("/api/v1/auth/register")
                .send({
                    email: identity,
                    masterSalt: "somemastersalt",
                    srpSalt: salt.toString("hex"),
                    srpVerifier: verifier.toString("hex"),
                    rsaPublicKey: "some-rsa-key",
                });
        });

        it("should complete the two-step login successfully and return a JWT", async () => {
            const initiateRes = await request(app)
                .post("/api/v1/auth/login/initiate")
                .send({ email: identity });

            expect(initiateRes.status).toBe(200);
            const { serverPublicEphemeral, challengeKey } = initiateRes.body;

            const clientSecret = await SRP.genKey(32);
            const client = new SrpClient(
                SRP.params[3072],
                salt,
                Buffer.from(identity),
                Buffer.from(password),
                clientSecret
            );

            const clientPublicEphemeral = client.computeA();

            client.setB(Buffer.from(serverPublicEphemeral, "hex"));

            const clientProof = client.computeM1();

            const verifyRes = await request(app)
                .post("/api/v1/auth/login/verify")
                .send({
                    challengeKey,
                    clientPublicEphemeral:
                        clientPublicEphemeral.toString("hex"),
                    clientProof: clientProof.toString("hex"),
                });

            expect(verifyRes.status).toBe(200);
            expect(verifyRes.body).toHaveProperty("token");
            expect(verifyRes.body.user).toHaveProperty("email", identity);
        });

        it("should fail with status 401 if the challengeKey is invalid", async () => {
            const initiateRes = await request(app)
                .post("/api/v1/auth/login/initiate")
                .send({ email: identity });

            expect(initiateRes.status).toBe(200);
            const { serverPublicEphemeral } = initiateRes.body;

            const clientSecret = await SRP.genKey(32);
            const client = new SrpClient(
                SRP.params[3072],
                salt,
                Buffer.from(identity),
                Buffer.from(password),
                clientSecret
            );
            const clientPublicEphemeral = client.computeA();
            client.setB(Buffer.from(serverPublicEphemeral, "hex"));
            const clientProof = client.computeM1();

            const verifyRes = await request(app)
                .post("/api/v1/auth/login/verify")
                .send({
                    challengeKey: "some-fake-or-expired-key",
                    clientPublicEphemeral:
                        clientPublicEphemeral.toString("hex"),
                    clientProof: clientProof.toString("hex"),
                });

            expect(verifyRes.status).toBe(401);
            expect(verifyRes.body).toHaveProperty(
                "message",
                "Invalid or expired login challenge. Please try again."
            );
        });

        it("should fail with status 401 if the client proof (M1) is incorrect", async () => {
            const initiateRes = await request(app)
                .post("/api/v1/auth/login/initiate")
                .send({ email: identity });

            expect(initiateRes.status).toBe(200);
            const { challengeKey } = initiateRes.body;

            const clientSecret = await SRP.genKey(32);
            const client = new SrpClient(
                SRP.params[3072],
                salt,
                Buffer.from(identity),
                Buffer.from(password),
                clientSecret
            );
            const clientPublicEphemeral = client.computeA();

            const wrongClientProof = await SRP.genKey(32);

            const verifyRes = await request(app)
                .post("/api/v1/auth/login/verify")
                .send({
                    challengeKey,
                    clientPublicEphemeral:
                        clientPublicEphemeral.toString("hex"),
                    clientProof: wrongClientProof.toString("hex"),
                });

            expect(verifyRes.status).toBe(401);
            expect(verifyRes.body).toHaveProperty(
                "message",
                "Invalid credentials. Login failed."
            );
        });
    });
});
