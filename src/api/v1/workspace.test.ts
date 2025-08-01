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
            srpSalt: "somesalt",
            srpVerifier: "someverifier",
            rsaPublicKey: "somekey",
        };
        const createdUser = await authService.registerUser(userInput);

        const tokenPayload = {
            userId: createdUser._id,
            email: createdUser.email,
        };
        userToken = jwt.sign(tokenPayload, config.jwt.secret, {
            expiresIn: "15m",
        });

        testUser = { ...createdUser.toObject() };
    });

    describe("GET /", () => {
        it("should fail with status 401 if no token is provided", async () => {
            const res = await request(app).get("/api/v1/workspaces");
            expect(res.status).toBe(401);
        });

        it("should return the user's personal workspace and any shared workspaces", async () => {
            const otherUser = await new User({
                email: "other-user@example.com",
                srpSalt: "salt2",
                srpVerifier: "verifier2",
                rsaPublicKey: "key2",
                defaultWorkspaceId: new mongoose.Types.ObjectId(),
            }).save();

            const sharedWorkspace = await new Workspace({
                ownerId: otherUser._id,
                name: "Shared Team Workspace",
            }).save();

            await new WorkspaceMember({
                workspaceId: testUser.defaultWorkspaceId,
                userId: testUser._id,
                role: WorkspaceRole.ADMIN,
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
});
