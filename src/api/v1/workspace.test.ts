import jwt from "jsonwebtoken";
import mongoose from "mongoose";
import request from "supertest";

import config from "@/config";
import User, { IUser } from "@/models/user.model";
import Workspace, { IWorkspace } from "@/models/workspace.model";
import WorkspaceMember from "@/models/workspaceMember.model";
import app from "@/server";
import * as authService from "@/services/auth.service";
import { WorkspaceRole } from "@/types";

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
            const otherUser = await new User({
                email: "other-user@example.com",
                masterSalt: "mastersalt2",
                srpSalt: "salt2",
                srpVerifier: "verifier2",
                rsaPublicKey: "key2",
                encryptedRsaPrivateKey: "encryptedkey2",
                encryptedRsaPrivateKeyIv: "encryptedkeyiv2",
                defaultWorkspaceId: new mongoose.Types.ObjectId(),
            }).save();

            const sharedWorkspace = await new Workspace({
                ownerId: otherUser._id,
                name: "Shared Team Workspace",
            }).save();

            await new WorkspaceMember({
                workspaceId: sharedWorkspace._id,
                userId: testUser._id,
                role: WorkspaceRole.MEMBER,
            }).save();

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
            expect(res.body.data).toHaveProperty(
                "ownerId",
                (testUser._id as mongoose.Types.ObjectId).toString()
            );

            const newWorkspaceId = res.body.data._id;

            const member = await WorkspaceMember.findOne({
                workspaceId: newWorkspaceId,
                userId: testUser._id,
            });

            expect(member).not.toBeNull();
            expect(member!.role).toBe(WorkspaceRole.ADMIN);
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
