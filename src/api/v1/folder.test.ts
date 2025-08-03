import jwt from "jsonwebtoken";
import mongoose from "mongoose";
import request from "supertest";

import config from "@/config";
import Folder, { IFolder } from "@/models/folder.model";
import { IUser } from "@/models/user.model";
import Workspace from "@/models/workspace.model";
import WorkspaceMember from "@/models/workspaceMember.model";
import app from "@/server";
import * as authService from "@/services/auth.service";
import { WorkspaceRole } from "@/types";

jest.mock("@/config/db");

describe("Folder Routes /api/v1/folders", () => {
    let adminUser: IUser;
    let managerUser: IUser;
    let memberUser: IUser;
    let adminToken: string;
    let managerToken: string;
    let memberToken: string;
    let personalWorkspaceId: string;

    const createUserAndToken = async (email: string) => {
        const user = await authService.registerUser({
            email,
            masterSalt: "mastersalt",
            srpSalt: "salt",
            srpVerifier: "verifier",
            rsaPublicKey: "key",
            encryptedRsaPrivateKey: "encryptedkey",
            encryptedRsaPrivateKeyIv: "encryptedkeyiv",
        });
        const token = jwt.sign(
            { userId: user._id, email: user.email },
            config.jwt.secret
        );
        return { user, token };
    };

    beforeEach(async () => {
        ({ user: adminUser, token: adminToken } = await createUserAndToken(
            "admin@test.com"
        ));
        ({ user: managerUser, token: managerToken } = await createUserAndToken(
            "manager@test.com"
        ));
        ({ user: memberUser, token: memberToken } = await createUserAndToken(
            "member@test.com"
        ));

        personalWorkspaceId = adminUser.defaultWorkspaceId.toString();

        await WorkspaceMember.insertMany([
            {
                workspaceId: personalWorkspaceId,
                userId: managerUser._id,
                role: WorkspaceRole.MANAGER,
            },
            {
                workspaceId: personalWorkspaceId,
                userId: memberUser._id,
                role: WorkspaceRole.MEMBER,
            },
        ]);
    });

    describe("POST /", () => {
        it("should allow an ADMIN to create a new folder", async () => {
            const res = await request(app)
                .post("/api/v1/folders")
                .set("Authorization", `Bearer ${adminToken}`)
                .send({
                    name: "Admin Folder",
                    workspaceId: personalWorkspaceId,
                });

            expect(res.status).toBe(201);
            expect(res.body.data).toHaveProperty("name", "Admin Folder");
        });

        it("should allow a MANAGER to create a new folder", async () => {
            const res = await request(app)
                .post("/api/v1/folders")
                .set("Authorization", `Bearer ${managerToken}`)
                .send({
                    name: "Manager Folder",
                    workspaceId: personalWorkspaceId,
                });

            expect(res.status).toBe(201);
            expect(res.body.data).toHaveProperty("name", "Manager Folder");
        });

        it("should FORBID a MEMBER from creating a new folder", async () => {
            const res = await request(app)
                .post("/api/v1/folders")
                .set("Authorization", `Bearer ${memberToken}`)
                .send({
                    name: "Member Folder",
                    workspaceId: personalWorkspaceId,
                });

            expect(res.status).toBe(403);
            expect(res.body).toHaveProperty(
                "message",
                "Forbidden: Only workspace admins or managers can create new folders."
            );
        });

        it("should allow an ADMIN to create a nested folder (subfolder)", async () => {
            const parentFolderRes = await request(app)
                .post("/api/v1/folders")
                .set("Authorization", `Bearer ${adminToken}`)
                .send({
                    name: "Parent Folder",
                    workspaceId: personalWorkspaceId,
                });
            const parentFolderId = parentFolderRes.body.data._id;

            const subfolderName = "Subfolder";
            const res = await request(app)
                .post("/api/v1/folders")
                .set("Authorization", `Bearer ${adminToken}`)
                .send({
                    name: subfolderName,
                    workspaceId: personalWorkspaceId,
                    parentId: parentFolderId,
                });

            expect(res.status).toBe(201);
            expect(res.body.data).toHaveProperty("name", subfolderName);
            expect(res.body.data).toHaveProperty("parentId", parentFolderId);

            const subfolder = await Folder.findById(res.body.data._id);
            expect(subfolder).not.toBeNull();
            expect(subfolder!.parentId!.toString()).toBe(parentFolderId);
        });

        it("should fail if trying to create a subfolder with a non-existent parentId", async () => {
            const fakeParentId = new mongoose.Types.ObjectId().toString();

            const res = await request(app)
                .post("/api/v1/folders")
                .set("Authorization", `Bearer ${adminToken}`)
                .send({
                    name: "Orphan Folder",
                    workspaceId: personalWorkspaceId,
                    parentId: fakeParentId,
                });

            expect(res.status).toBe(500);
            expect(res.body.error).toContain("Parent folder not found");
        });
    });

    describe("GET /", () => {
        it("should get all folders for a given workspace", async () => {
            await new Folder({
                ownerId: adminUser._id,
                workspaceId: personalWorkspaceId,
                name: "Work",
            }).save();
            await new Folder({
                ownerId: managerUser._id,
                workspaceId: personalWorkspaceId,
                name: "Personal Projects",
            }).save();

            const otherWorkspace = await new Workspace({
                ownerId: adminUser._id,
                name: "Other",
            }).save();
            await new Folder({
                ownerId: adminUser._id,
                workspaceId: otherWorkspace._id,
                name: "Secret",
            }).save();

            const res = await request(app)
                .get(`/api/v1/folders?workspaceId=${personalWorkspaceId}`)
                .set("Authorization", `Bearer ${adminToken}`);

            expect(res.status).toBe(200);
            expect(res.body.data).toBeInstanceOf(Array);
            expect(res.body.data.length).toBe(3);
            const folderNames = res.body.data.map((f: IFolder) => f.name);
            expect(folderNames).toContain("Work");
            expect(folderNames).toContain("Personal Projects");
            expect(folderNames).not.toContain("Secret");
        });

        it("should fail with status 403 if user tries to get folders from a workspace they are not in", async () => {
            const anotherWorkspaceId = new mongoose.Types.ObjectId().toString();
            const res = await request(app)
                .get(`/api/v1/folders?workspaceId=${anotherWorkspaceId}`)
                .set("Authorization", `Bearer ${adminToken}`);

            expect(res.status).toBe(403);
        });
    });
});
