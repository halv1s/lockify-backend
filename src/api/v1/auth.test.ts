import { SRP, SrpClient } from "fast-srp-hap";
import request from "supertest";

import Relation from "@/models/relation.model";
import User from "@/models/user.model";
import app from "@/server";
import { ReBACNamespace, ReBACRelation } from "@/types";

jest.mock("@/config/db");

describe("Auth Routes /api/v1/auth", () => {
    describe("POST /register", () => {
        const testUser = {
            email: "test@example.com",
            masterSalt: "somemastersalt",
            srpSalt: "somesalt",
            srpVerifier: "someverifier",
            rsaPublicKey: "somekey",
            encryptedRsaPrivateKey: "someencryptedkey",
            encryptedRsaPrivateKeyIv: "some-encrypted-rsa-key-iv",
        };

        it("should register a new user and create default relations for workspace and folder", async () => {
            const res = await request(app)
                .post("/api/v1/auth/register")
                .send(testUser);

            expect(res.status).toBe(201);
            expect(res.body.user).toHaveProperty("email", testUser.email);

            const user = await User.findOne({ email: testUser.email });
            expect(user).not.toBeNull();

            const userId = user!._id;
            const workspaceId = user!.defaultWorkspaceId;

            const userSubject = `${ReBACNamespace.USERS}:${userId}`;
            const workspaceObject = `${ReBACNamespace.WORKSPACES}:${workspaceId}`;

            const ownerRelation = await Relation.findOne({
                subject: userSubject,
                relation: ReBACRelation.OWNER,
                object: workspaceObject,
            });
            const adminRelation = await Relation.findOne({
                subject: userSubject,
                relation: ReBACRelation.ADMIN,
                object: workspaceObject,
            });

            expect(ownerRelation).not.toBeNull();
            expect(adminRelation).not.toBeNull();

            const folderRelation = await Relation.findOne({
                relation: ReBACRelation.OWNER,
                object: new RegExp(`^${ReBACNamespace.FOLDERS}:`),
            });
            expect(folderRelation).not.toBeNull();
            expect(folderRelation!.subject).toBe(userSubject);

            const parentRelation = await Relation.findOne({
                subject: folderRelation!.object,
                relation: ReBACRelation.PARENT,
            });
            expect(parentRelation).not.toBeNull();
            expect(parentRelation!.object).toBe(workspaceObject);
        });

        it("should fail with status 409 if email already exists", async () => {
            await request(app).post("/api/v1/auth/register").send(testUser);
            const res = await request(app)
                .post("/api/v1/auth/register")
                .send(testUser);
            expect(res.status).toBe(409);
        });

        it("should fail with status 400 if required fields are missing", async () => {
            const res = await request(app)
                .post("/api/v1/auth/register")
                .send({ email: "test@example.com" });
            expect(res.status).toBe(400);
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
                    encryptedRsaPrivateKey: "some-encrypted-rsa-key",
                    encryptedRsaPrivateKeyIv: "some-encrypted-rsa-key-iv",
                });
        });

        it("should complete the two-step login successfully and return a JWT", async () => {
            const initiateRes = await request(app)
                .post("/api/v1/auth/login/initiate")
                .send({ email: identity });
            const { serverPublicEphemeral, challengeKey } = initiateRes.body;
            const client = new SrpClient(
                SRP.params[3072],
                salt,
                Buffer.from(identity),
                Buffer.from(password),
                await SRP.genKey(32)
            );
            client.setB(Buffer.from(serverPublicEphemeral, "hex"));
            const clientPublicEphemeral = client.computeA();
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
        });
    });
});
