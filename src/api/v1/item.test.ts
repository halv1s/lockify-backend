import jwt from "jsonwebtoken";
import mongoose from "mongoose";
import request from "supertest";

import config from "@/config";
import Folder, { IFolder } from "@/models/folder.model";
import Item, { IItem } from "@/models/item.model";
import Relation from "@/models/relation.model";
import { IUser } from "@/models/user.model";
import app from "@/server";
import * as authService from "@/services/auth.service";
import { ItemType, ReBACNamespace, ReBACRelation } from "@/types";

jest.mock("@/config/db");

describe("Item Routes /api/v1/items", () => {
    let owner: IUser;
    let editor: IUser;
    let viewer: IUser;
    let _outsider: IUser;
    let ownerToken: string;
    let editorToken: string;
    let viewerToken: string;
    let outsiderToken: string;
    let folder: IFolder;
    let sharedItem: IItem;

    const createUserAndToken = async (email: string) => {
        const user = await authService.registerUser({
            email,
            masterSalt: "mastersalt",
            srpSalt: "s",
            srpVerifier: "v",
            rsaPublicKey: "k",
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
        ({ user: editor, token: editorToken } = await createUserAndToken(
            "editor@test.com"
        ));
        ({ user: viewer, token: viewerToken } = await createUserAndToken(
            "viewer@test.com"
        ));
        ({ user: _outsider, token: outsiderToken } = await createUserAndToken(
            "outsider@test.com"
        ));

        folder = await new Folder({
            workspaceId: owner.defaultWorkspaceId,
            name: "Test Folder",
        }).save();

        const item = await new Item({
            folderId: folder._id,
            type: ItemType.LOGIN,
            displayMetadata: { title: "Shared API Key" },
            encryptedData: "super-secret-data",
            encryptedDataIv: "super-secret-data-iv",
            encryptedRecordKey: "super-secret-key",
            encryptedRecordKeyIv: "super-secret-key-iv",
        }).save();
        sharedItem = item.toObject();

        await Relation.insertMany([
            // 1. Owner owns the folder and the item
            {
                subject: `${ReBACNamespace.USERS}:${owner._id}`,
                relation: ReBACRelation.OWNER,
                object: `${ReBACNamespace.FOLDERS}:${folder._id}`,
            },
            {
                subject: `${ReBACNamespace.USERS}:${owner._id}`,
                relation: ReBACRelation.OWNER,
                object: `${ReBACNamespace.ITEMS}:${sharedItem._id}`,
            },
            // 2. The item belongs to the folder (parent-child relationship)
            {
                subject: `${ReBACNamespace.ITEMS}:${sharedItem._id}`,
                relation: ReBACRelation.PARENT,
                object: `${ReBACNamespace.FOLDERS}:${folder._id}`,
            },
            // 3. Editor has 'editor' role on the item
            {
                subject: `${ReBACNamespace.USERS}:${editor._id}`,
                relation: ReBACRelation.EDITOR,
                object: `${ReBACNamespace.ITEMS}:${sharedItem._id}`,
                encryptedKey: "key-for-editor",
            },
            // 4. Viewer has 'viewer' role on the item
            {
                subject: `${ReBACNamespace.USERS}:${viewer._id}`,
                relation: ReBACRelation.VIEWER,
                object: `${ReBACNamespace.ITEMS}:${sharedItem._id}`,
                encryptedKey: "key-for-viewer",
            },
        ]);
    });

    describe("GET /:itemId", () => {
        it("should allow the owner to get the item details", async () => {
            const res = await request(app)
                .get(`/api/v1/items/${sharedItem._id}`)
                .set("Authorization", `Bearer ${ownerToken}`);
            expect(res.status).toBe(200);
            expect(res.body.data.encryptedData).toBe("super-secret-data");
        });

        it("should allow a user with share permissions (viewer) to get the item details", async () => {
            const res = await request(app)
                .get(`/api/v1/items/${sharedItem._id}`)
                .set("Authorization", `Bearer ${viewerToken}`);
            expect(res.status).toBe(200);
        });

        it("should FORBID an outsider from getting the item details", async () => {
            const res = await request(app)
                .get(`/api/v1/items/${sharedItem._id}`)
                .set("Authorization", `Bearer ${outsiderToken}`);
            expect(res.status).toBe(403);
        });
    });

    describe("POST /", () => {
        it("should allow a user with 'editor' permission on a folder to create an item in it", async () => {
            const newFolder = await new Folder({
                workspaceId: owner.defaultWorkspaceId,
                name: "Editor Test Folder",
            }).save();
            await new Relation({
                subject: `${ReBACNamespace.USERS}:${editor._id}`,
                relation: ReBACRelation.EDITOR,
                object: `${ReBACNamespace.FOLDERS}:${newFolder._id}`,
                encryptedKey: "key-for-editor",
            }).save();

            const res = await request(app)
                .post("/api/v1/items")
                .set("Authorization", `Bearer ${editorToken}`)
                .send({
                    folderId: (
                        newFolder._id as mongoose.Types.ObjectId
                    ).toString(),
                    type: ItemType.API_KEY,
                    encryptedData: "some-api-data",
                    encryptedDataIv: "iv",
                    encryptedRecordKey: "some-api-key",
                    encryptedRecordKeyIv: "iv",
                });

            expect(res.status).toBe(201);
            expect(res.body.data).toHaveProperty(
                "folderId",
                (newFolder._id as mongoose.Types.ObjectId).toString()
            );
        });

        it("should FORBID a user with 'viewer' permission on a folder from creating an item", async () => {
            const newFolder = await new Folder({
                workspaceId: owner.defaultWorkspaceId,
                name: "Viewer Test Folder",
            }).save();
            await new Relation({
                subject: `${ReBACNamespace.USERS}:${viewer._id}`,
                relation: ReBACRelation.VIEWER,
                object: `${ReBACNamespace.FOLDERS}:${newFolder._id}`,
                encryptedKey: "key-for-viewer",
            }).save();

            const res = await request(app)
                .post("/api/v1/items")
                .set("Authorization", `Bearer ${viewerToken}`)
                .send({
                    folderId: (
                        newFolder._id as mongoose.Types.ObjectId
                    ).toString(),
                    type: ItemType.LOGIN,
                    encryptedData: "some-data",
                    encryptedDataIv: "iv",
                    encryptedRecordKey: "some-key",
                    encryptedRecordKeyIv: "iv",
                });

            expect(res.status).toBe(403);
            expect(res.body.message).toContain(
                "Forbidden: You do not have permission to create items in this folder."
            );
        });
    });

    describe("PUT /:itemId", () => {
        it("should allow the owner to update the item", async () => {
            const res = await request(app)
                .put(`/api/v1/items/${sharedItem._id}`)
                .set("Authorization", `Bearer ${ownerToken}`)
                .send({
                    encryptedData: "new-data",
                    encryptedDataIv: "new-data-iv",
                });

            expect(res.status).toBe(200);
            expect(res.body.data.encryptedData).toBe("new-data");
        });

        it("should allow a user with 'editor' permission to update the item", async () => {
            const res = await request(app)
                .put(`/api/v1/items/${sharedItem._id}`)
                .set("Authorization", `Bearer ${editorToken}`)
                .send({ displayMetadata: { title: "Updated Title" } });

            expect(res.status).toBe(200);
            expect(res.body.data.displayMetadata.title).toBe("Updated Title");
        });

        it("should FORBID a user with 'viewer' permission from updating the item", async () => {
            const res = await request(app)
                .put(`/api/v1/items/${sharedItem._id}`)
                .set("Authorization", `Bearer ${viewerToken}`)
                .send({ encryptedData: "forbidden-data" });

            expect(res.status).toBe(403);
        });
    });

    describe("DELETE /:itemId", () => {
        it("should allow the owner to delete the item", async () => {
            const res = await request(app)
                .delete(`/api/v1/items/${sharedItem._id}`)
                .set("Authorization", `Bearer ${ownerToken}`);

            expect(res.status).toBe(200);
            const item = await Item.findById(sharedItem._id);
            expect(item).toBeNull();
        });

        it("should ALLOW a user with 'editor' permission to delete the item", async () => {
            const res = await request(app)
                .delete(`/api/v1/items/${sharedItem._id}`)
                .set("Authorization", `Bearer ${editorToken}`);

            expect(res.status).toBe(200);
            const item = await Item.findById(sharedItem._id);
            expect(item).toBeNull();
        });

        it("should FORBID a user with 'viewer' permission from deleting the item", async () => {
            const res = await request(app)
                .delete(`/api/v1/items/${sharedItem._id}`)
                .set("Authorization", `Bearer ${viewerToken}`);

            expect(res.status).toBe(403);
        });
    });
});
