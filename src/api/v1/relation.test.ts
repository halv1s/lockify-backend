import jwt from "jsonwebtoken";
import mongoose from "mongoose";
import request from "supertest";

import config from "@/config";
import Folder, { IFolder } from "@/models/folder.model";
import Relation from "@/models/relation.model";
import { IUser } from "@/models/user.model";
import app from "@/server";
import * as authService from "@/services/auth.service";
import { ReBACNamespace, ReBACRelation } from "@/types";

jest.mock("@/config/db");

describe("Relation Routes /api/v1/relations", () => {
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
        ({ user: owner, token: ownerToken } = await createUserAndToken(
            "owner@test.com"
        ));
        ({ user: recipient, token: recipientToken } = await createUserAndToken(
            "recipient@test.com"
        ));
        ({ user: _thirdParty } = await createUserAndToken(
            "thirdparty@test.com"
        ));

        const folder = new Folder({
            workspaceId: owner.defaultWorkspaceId,
            name: "Shared Project",
        });
        await folder.save();
        testFolder = folder;

        await new Relation({
            subject: `${ReBACNamespace.USERS}:${owner._id}`,
            relation: ReBACRelation.OWNER,
            object: `${ReBACNamespace.FOLDERS}:${testFolder._id}`,
        }).save();
    });

    describe("POST /", () => {
        const sharePayload = {
            recipientEmail: "recipient@test.com",
            targetId: "", // Will be set in the test
            targetType: ReBACNamespace.FOLDERS,
            permissions: ReBACRelation.EDITOR,
            encryptedKey: "encrypted-folder-key-for-recipient",
        };

        it("should allow an owner to share a resource successfully", async () => {
            const payload = {
                ...sharePayload,
                targetId: (
                    testFolder._id as mongoose.Types.ObjectId
                ).toString(),
            };

            const res = await request(app)
                .post("/api/v1/relations")
                .set("Authorization", `Bearer ${ownerToken}`)
                .send(payload);

            expect(res.status).toBe(201);

            const expectedSubject = `${ReBACNamespace.USERS}:${recipient._id}`;
            const expectedObject = `${ReBACNamespace.FOLDERS}:${testFolder._id}`;

            expect(res.body.data).toHaveProperty("subject", expectedSubject);
            expect(res.body.data).toHaveProperty("object", expectedObject);
            expect(res.body.data).toHaveProperty(
                "relation",
                ReBACRelation.EDITOR
            );

            const relation = await Relation.findOne({
                subject: expectedSubject,
                object: expectedObject,
            });
            expect(relation).not.toBeNull();
            expect(relation!.encryptedKey).toBe(sharePayload.encryptedKey);
        });

        it("should fail with status 403 if a user tries to share a resource they do not own", async () => {
            const res = await request(app)
                .post("/api/v1/relations")
                .set("Authorization", `Bearer ${recipientToken}`)
                .send({
                    recipientEmail: "thirdparty@test.com",
                    targetId: (
                        testFolder._id as mongoose.Types.ObjectId
                    ).toString(),
                    targetType: ReBACNamespace.FOLDERS,
                    permissions: ReBACRelation.EDITOR,
                    encryptedKey: "key",
                });

            expect(res.status).toBe(403);
            expect(res.body.message).toContain(
                "Forbidden: You can only share resources you own."
            );
        });

        it("should fail with status 404 if the recipient email does not exist", async () => {
            const res = await request(app)
                .post("/api/v1/relations")
                .set("Authorization", `Bearer ${ownerToken}`)
                .send({
                    ...sharePayload,
                    targetId: (
                        testFolder._id as mongoose.Types.ObjectId
                    ).toString(),
                    recipientEmail: "ghost@test.com",
                });

            expect(res.status).toBe(404);
            expect(res.body.message).toContain("Recipient user not found.");
        });

        it("should fail with status 400 if a user tries to share a resource with themselves", async () => {
            const res = await request(app)
                .post("/api/v1/relations")
                .set("Authorization", `Bearer ${ownerToken}`)
                .send({
                    ...sharePayload,
                    targetId: (
                        testFolder._id as mongoose.Types.ObjectId
                    ).toString(),
                    recipientEmail: owner.email,
                });

            expect(res.status).toBe(400);
            expect(res.body.message).toContain(
                "You cannot share a resource with yourself."
            );
        });
    });
});
