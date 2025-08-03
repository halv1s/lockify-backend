import jwt from "jsonwebtoken";
import mongoose from "mongoose";
import request from "supertest";

import config from "@/config";
import Folder from "@/models/folder.model";
import Relation from "@/models/relation.model";
import { IUser } from "@/models/user.model";
import app from "@/server";
import * as authService from "@/services/auth.service";
import { ReBACNamespace, ReBACRelation } from "@/types";

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

        const workspaceObject = `${ReBACNamespace.WORKSPACES}:${personalWorkspaceId}`;
        await Relation.insertMany([
            // The `adminUser` is already an admin of `personalWorkspaceId` via registerUser.
            // Add managerUser as a MANAGER
            {
                subject: `${ReBACNamespace.USERS}:${managerUser._id}`,
                relation: ReBACRelation.MANAGER,
                object: workspaceObject,
            },
            // Add memberUser as a MEMBER
            {
                subject: `${ReBACNamespace.USERS}:${memberUser._id}`,
                relation: ReBACRelation.MEMBER,
                object: workspaceObject,
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

            const res = await request(app)
                .post("/api/v1/folders")
                .set("Authorization", `Bearer ${adminToken}`)
                .send({
                    name: "Subfolder",
                    workspaceId: personalWorkspaceId,
                    parentId: parentFolderId,
                });

            expect(res.status).toBe(201);

            const childObject = `${ReBACNamespace.FOLDERS}:${res.body.data._id}`;
            const parentObject = `${ReBACNamespace.FOLDERS}:${parentFolderId}`;
            const parentRelation = await Relation.findOne({
                subject: childObject,
                relation: ReBACRelation.PARENT,
                object: parentObject,
            });
            expect(parentRelation).not.toBeNull();
        });

        // This test case remains the same as it tests for invalid input
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
        it("should get all folders for a given workspace if user is a member", async () => {
            await new Folder({
                workspaceId: personalWorkspaceId,
                name: "Work",
            }).save();
            await new Folder({
                workspaceId: personalWorkspaceId,
                name: "Personal Projects",
            }).save();

            const res = await request(app)
                .get(`/api/v1/folders?workspaceId=${personalWorkspaceId}`)
                .set("Authorization", `Bearer ${memberToken}`);

            expect(res.status).toBe(200);
            expect(res.body.data).toBeInstanceOf(Array);
            expect(res.body.data.length).toBe(3); // Including the "Uncategorized" folder
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
