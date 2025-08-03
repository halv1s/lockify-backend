import jwt from "jsonwebtoken";
import request from "supertest";

import config from "@/config";
import Relation from "@/models/relation.model";
import { IUser } from "@/models/user.model";
import Workspace, { IWorkspace } from "@/models/workspace.model";
import app from "@/server";
import * as authService from "@/services/auth.service";
import { ReBACNamespace, ReBACRelation } from "@/types";

jest.mock("@/config/db");

describe("Workspace Routes /api/v1/workspaces", () => {
    let testUser: IUser;
    let userToken: string;

    beforeEach(async () => {
        const userInput = {
            email: "workspace-user@example.com",
            masterSalt: "mastersalt",
            srpSalt: "somesalt",
            srpVerifier: "someverifier",
            rsaPublicKey: "somekey",
            encryptedRsaPrivateKey: "encryptedkey",
            encryptedRsaPrivateKeyIv: "encryptedkeyiv",
        };
        const createdUser = await authService.registerUser(userInput);

        const tokenPayload = {
            userId: createdUser._id,
            email: createdUser.email,
        };
        userToken = jwt.sign(tokenPayload, config.jwt.secret, {
            expiresIn: "15m",
        });
        testUser = createdUser;
    });

    describe("GET /", () => {
        it("should fail with status 401 if no token is provided", async () => {
            const res = await request(app).get("/api/v1/workspaces");
            expect(res.status).toBe(401);
        });

        it("should return the user's personal workspace and any shared workspaces", async () => {
            const otherUser = await authService.registerUser({
                email: "other-user@example.com",
                masterSalt: "ms2",
                srpSalt: "s2",
                srpVerifier: "v2",
                rsaPublicKey: "k2",
                encryptedRsaPrivateKey: "ek2",
                encryptedRsaPrivateKeyIv: "eki2",
            });

            const sharedWorkspace = await new Workspace({
                name: "Shared Team Workspace",
            }).save();

            await Relation.insertMany([
                // Other user owns the shared workspace
                {
                    subject: `${ReBACNamespace.USERS}:${otherUser._id}`,
                    relation: ReBACRelation.OWNER,
                    object: `${ReBACNamespace.WORKSPACES}:${sharedWorkspace._id}`,
                },
                // testUser is a member of the shared workspace
                {
                    subject: `${ReBACNamespace.USERS}:${testUser._id}`,
                    relation: ReBACRelation.MEMBER,
                    object: `${ReBACNamespace.WORKSPACES}:${sharedWorkspace._id}`,
                },
            ]);

            const res = await request(app)
                .get("/api/v1/workspaces")
                .set("Authorization", `Bearer ${userToken}`);

            expect(res.status).toBe(200);
            expect(res.body.data).toBeInstanceOf(Array);
            expect(res.body.data.length).toBe(2);

            const workspaceNames = res.body.data.map(
                (ws: IWorkspace) => ws.name
            );
            expect(workspaceNames).toContain("Personal");
            expect(workspaceNames).toContain("Shared Team Workspace");
        });
    });

    describe("POST /", () => {
        it("should create a new workspace successfully and add the creator as an admin member", async () => {
            const workspaceName = "My New Team";

            const res = await request(app)
                .post("/api/v1/workspaces")
                .set("Authorization", `Bearer ${userToken}`)
                .send({ name: workspaceName });

            expect(res.status).toBe(201);
            expect(res.body.data).toHaveProperty("name", workspaceName);

            const newWorkspaceId = res.body.data._id;
            const newWorkspaceObject = `${ReBACNamespace.WORKSPACES}:${newWorkspaceId}`;

            const ownerRelation = await Relation.findOne({
                subject: `${ReBACNamespace.USERS}:${testUser._id}`,
                relation: ReBACRelation.OWNER,
                object: newWorkspaceObject,
            });
            const adminRelation = await Relation.findOne({
                subject: `${ReBACNamespace.USERS}:${testUser._id}`,
                relation: ReBACRelation.ADMIN,
                object: newWorkspaceObject,
            });

            expect(ownerRelation).not.toBeNull();
            expect(adminRelation).not.toBeNull();
        });

        it("should fail with status 400 if the workspace name is missing", async () => {
            const res = await request(app)
                .post("/api/v1/workspaces")
                .set("Authorization", `Bearer ${userToken}`)
                .send({});

            expect(res.status).toBe(400);
            expect(res.body).toHaveProperty(
                "message",
                "Workspace name is required"
            );
        });
    });
});
