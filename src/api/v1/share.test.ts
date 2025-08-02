import jwt from "jsonwebtoken";
import mongoose from "mongoose";
import request from "supertest";

import config from "@/config";
import Folder, { IFolder } from "@/models/folder.model";
import Share from "@/models/share.model";
import { IUser } from "@/models/user.model";
import app from "@/server";
import * as authService from "@/services/auth.service";
import { FolderPermissions, ShareTargetType } from "@/types";

jest.mock("@/config/db");

describe("Share Routes /api/v1/shares", () => {
    let owner: IUser;
    let recipient: IUser;
    let _thirdParty: IUser;
    let ownerToken: string;
    let recipientToken: string;
    let testFolder: IFolder;

    const createUserAndToken = async (email: string) => {
        const user = await authService.registerUser({
            email,
            masterSalt: "mastersalt",
            srpSalt: "salt",
            srpVerifier: "verifier",
            rsaPublicKey: "key",
        });
        const token = jwt.sign(
            { userId: user._id, email: user.email },
            config.jwt.secret
        );
        return { user, token };
    };

    beforeEach(async () => {
        ({ user: owner, token: ownerToken } = await createUserAndToken(
            "owner@test.com"
        ));
        ({ user: recipient, token: recipientToken } = await createUserAndToken(
            "recipient@test.com"
        ));
        ({ user: _thirdParty } = await createUserAndToken(
            "thirdparty@test.com"
        ));

        testFolder = await new Folder({
            ownerId: owner._id,
            workspaceId: owner.defaultWorkspaceId,
            name: "Shared Project",
        }).save();
    });

    describe("POST /", () => {
        const sharePayload = {
            recipientEmail: "recipient@test.com",
            targetType: ShareTargetType.FOLDER,
            permissions: FolderPermissions.EDIT,
            encryptedKey: "encrypted-folder-key-for-recipient",
        };

        it("should allow an owner to share a resource successfully", async () => {
            const res = await request(app)
                .post("/api/v1/shares")
                .set("Authorization", `Bearer ${ownerToken}`)
                .send({ ...sharePayload, targetId: testFolder._id });

            expect(res.status).toBe(201);
            expect(res.body.data).toHaveProperty(
                "userId",
                (recipient._id as mongoose.Types.ObjectId).toString()
            );
            expect(res.body.data).toHaveProperty(
                "targetId",
                (testFolder._id as mongoose.Types.ObjectId).toString()
            );
            expect(res.body.data).toHaveProperty(
                "permissions",
                FolderPermissions.EDIT
            );

            const share = await Share.findById(res.body.data._id);
            expect(share).not.toBeNull();
            expect(share!.encryptedKey).toBe(sharePayload.encryptedKey);
        });

        it("should fail with status 403 if a user tries to share a resource they do not own", async () => {
            const res = await request(app)
                .post("/api/v1/shares")
                .set("Authorization", `Bearer ${recipientToken}`)
                .send({
                    recipientEmail: "thirdparty@test.com",
                    targetId: testFolder._id,
                    targetType: ShareTargetType.FOLDER,
                    permissions: FolderPermissions.EDIT,
                    encryptedKey: "key",
                });

            expect(res.status).toBe(403);
            expect(res.body.message).toContain(
                "Forbidden: You can only share folders you own."
            );
        });

        it("should fail with status 404 if the recipient email does not exist", async () => {
            const res = await request(app)
                .post("/api/v1/shares")
                .set("Authorization", `Bearer ${ownerToken}`)
                .send({
                    ...sharePayload,
                    targetId: testFolder._id,
                    recipientEmail: "ghost@test.com",
                });

            expect(res.status).toBe(404);
            expect(res.body.message).toContain("Recipient user not found.");
        });

        it("should fail with status 400 if a user tries to share a resource with themselves", async () => {
            const res = await request(app)
                .post("/api/v1/shares")
                .set("Authorization", `Bearer ${ownerToken}`)
                .send({
                    ...sharePayload,
                    targetId: testFolder._id,
                    recipientEmail: owner.email,
                });

            expect(res.status).toBe(400);
            expect(res.body.message).toContain(
                "You cannot share a resource with yourself."
            );
        });
    });
});
