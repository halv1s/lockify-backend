import { webcrypto } from "crypto";
import { scrypt } from "crypto";
import { promisify } from "util";

import { SRP, SrpClient } from "fast-srp-hap";
import request from "supertest";

import Share from "@/models/share.model";
import User from "@/models/user.model";
import app from "@/server";
import { FolderPermissions, ItemType, ShareTargetType } from "@/types";

jest.mock("@/config/db");

// Helper function to simulate SRP client-side login
const simulateSrpClientLogin = async (
    email: string,
    password: string,
    srpSalt: Buffer,
    serverPublicEphemeral: string
) => {
    const clientSecret = await SRP.genKey(32);
    const client = new SrpClient(
        SRP.params[3072],
        srpSalt,
        Buffer.from(email),
        Buffer.from(password),
        clientSecret
    );
    const clientPublicEphemeral = client.computeA();
    client.setB(Buffer.from(serverPublicEphemeral, "hex"));
    const clientProof = client.computeM1();
    return {
        clientPublicEphemeral: clientPublicEphemeral.toString("hex"),
        clientProof: clientProof.toString("hex"),
    };
};

// Helper to derive Master Key from password and salt using scrypt (as a strong KDF)
const scryptAsync = promisify(scrypt);
async function deriveMasterKey(
    password: string,
    salt: string
): Promise<CryptoKey> {
    const keyBytes = await scryptAsync(password, Buffer.from(salt, "hex"), 32);
    return webcrypto.subtle.importKey(
        "raw",
        keyBytes as ArrayBuffer,
        { name: "AES-GCM" },
        false, // not extractable
        ["encrypt", "decrypt"]
    );
}

// Helper to encrypt an AES key using another AES key (for Master Key -> Item Key)
async function aesKeyEncrypt(itemKey: CryptoKey, masterKey: CryptoKey) {
    const iv = webcrypto.getRandomValues(new Uint8Array(12));
    const exportedItemKey = await webcrypto.subtle.exportKey("raw", itemKey);
    const encryptedItemKey = await webcrypto.subtle.encrypt(
        {
            name: "AES-GCM",
            iv: iv,
        },
        masterKey,
        exportedItemKey
    );
    return {
        ciphertext: Buffer.from(encryptedItemKey).toString("base64"),
        iv: Buffer.from(iv).toString("base64"),
    };
}

// Helper to decrypt an AES key using another AES key
async function aesKeyDecrypt(
    encryptedBase64: string,
    masterKey: CryptoKey,
    ivBase64: string
) {
    const encryptedArrayBuffer = Buffer.from(encryptedBase64, "base64");
    const iv = Buffer.from(ivBase64, "base64");
    const decryptedItemKeyRaw = await webcrypto.subtle.decrypt(
        {
            name: "AES-GCM",
            iv: iv,
        },
        masterKey,
        encryptedArrayBuffer
    );
    return webcrypto.subtle.importKey(
        "raw",
        decryptedItemKeyRaw,
        { name: "AES-GCM", length: 256 },
        true,
        ["encrypt", "decrypt"]
    );
}

// Helper to generate AES key (raw bytes)
async function generateAesKey() {
    const aesKey = await webcrypto.subtle.generateKey(
        {
            name: "AES-GCM",
            length: 256,
        },
        true,
        ["encrypt", "decrypt"]
    );
    return aesKey;
}

// Helper to encrypt data using AES-GCM
async function aesEncrypt(data: string, key: CryptoKey) {
    const iv = webcrypto.getRandomValues(new Uint8Array(12));
    const encryptedContent = await webcrypto.subtle.encrypt(
        {
            name: "AES-GCM",
            iv: iv,
        },
        key,
        new TextEncoder().encode(data)
    );
    return {
        ciphertext: Buffer.from(encryptedContent).toString("base64"),
        iv: Buffer.from(iv).toString("base64"),
    };
}

// Helper to decrypt data using AES-GCM
async function aesDecrypt(
    encryptedBase64: string,
    key: CryptoKey,
    ivBase64: string
) {
    const encryptedArrayBuffer = Buffer.from(encryptedBase64, "base64");
    const iv = Buffer.from(ivBase64, "base64");
    const decryptedContent = await webcrypto.subtle.decrypt(
        {
            name: "AES-GCM",
            iv: iv,
        },
        key,
        encryptedArrayBuffer
    );
    return new TextDecoder().decode(decryptedContent);
}

// Helper to generate RSA key pair (JWK format)
async function generateRsaKeyPair() {
    const { publicKey, privateKey } = await webcrypto.subtle.generateKey(
        {
            name: "RSA-OAEP",
            modulusLength: 2048,
            publicExponent: new Uint8Array([0x01, 0x00, 0x01]),
            hash: "SHA-256",
        },
        true,
        ["encrypt", "decrypt"]
    );
    const exportedPublicKey = await webcrypto.subtle.exportKey(
        "jwk",
        publicKey
    );
    const exportedPrivateKey = await webcrypto.subtle.exportKey(
        "jwk",
        privateKey
    );
    return { publicKey: exportedPublicKey, privateKey: exportedPrivateKey };
}

// Helper to encrypt AES key using RSA-OAEP public key
async function rsaEncrypt(aesKey: CryptoKey, rsaPublicKey: JsonWebKey) {
    const exportedAesKey = await webcrypto.subtle.exportKey("raw", aesKey);
    const importedRsaPublicKey = await webcrypto.subtle.importKey(
        "jwk",
        rsaPublicKey,
        { name: "RSA-OAEP", hash: "SHA-256" },
        false,
        ["encrypt"]
    );
    const encryptedKey = await webcrypto.subtle.encrypt(
        {
            name: "RSA-OAEP",
        },
        importedRsaPublicKey,
        exportedAesKey
    );
    return Buffer.from(encryptedKey).toString("base64");
}

// Helper to decrypt AES key using RSA-OAEP private key
async function rsaDecrypt(encryptedBase64: string, rsaPrivateKey: JsonWebKey) {
    const encryptedArrayBuffer = Buffer.from(encryptedBase64, "base64");
    const importedRsaPrivateKey = await webcrypto.subtle.importKey(
        "jwk",
        rsaPrivateKey,
        { name: "RSA-OAEP", hash: "SHA-256" },
        false,
        ["decrypt"]
    );
    const decryptedKeyRaw = await webcrypto.subtle.decrypt(
        {
            name: "RSA-OAEP",
        },
        importedRsaPrivateKey,
        encryptedArrayBuffer
    );
    return webcrypto.subtle.importKey(
        "raw",
        decryptedKeyRaw,
        { name: "AES-GCM", length: 256 },
        true,
        ["encrypt", "decrypt"]
    );
}

describe("End-to-End User Flow Tests", () => {
    let testUserEmail: string;
    let testUserPassword: string;
    let userToken: string;
    let personalWorkspaceId: string;
    let createdItemId: string;
    let userMasterSalt: string;
    let userMasterKey: CryptoKey;
    let rsaKeyPair: { publicKey: JsonWebKey; privateKey: JsonWebKey };

    beforeEach(async () => {
        testUserEmail = `e2e-user-${Date.now()}@lockify.com`;
        testUserPassword = "VerySecurePassword123!";
        userToken = "";
        personalWorkspaceId = "";
        createdItemId = "";
        userMasterSalt = webcrypto
            .getRandomValues(new Uint8Array(16))
            .toString();
        rsaKeyPair = await generateRsaKeyPair();
    });

    it("should allow a full user journey: register, login, create folder in default workspace, create item, retrieve item", async () => {
        // --- Step 1: Register a new user with Master Salt and RSA Key ---
        const srpSalt = await SRP.genKey(32);
        const srpVerifier = SRP.computeVerifier(
            SRP.params[3072],
            srpSalt,
            Buffer.from(testUserEmail),
            Buffer.from(testUserPassword)
        );

        userMasterKey = await deriveMasterKey(testUserPassword, userMasterSalt);

        const {
            ciphertext: encryptedRsaPrivateKey,
            iv: encryptedRsaPrivateKeyIv,
        } = await aesEncrypt(
            JSON.stringify(rsaKeyPair.privateKey),
            userMasterKey
        );

        const registerRes = await request(app)
            .post("/api/v1/auth/register")
            .send({
                email: testUserEmail,
                masterSalt: userMasterSalt,
                srpSalt: srpSalt.toString("hex"),
                srpVerifier: srpVerifier.toString("hex"),
                rsaPublicKey: JSON.stringify(rsaKeyPair.publicKey),
                encryptedRsaPrivateKey,
                encryptedRsaPrivateKeyIv,
            });

        expect(registerRes.status).toBe(201);
        const registeredUser = await User.findOne({ email: testUserEmail });
        personalWorkspaceId = registeredUser!.defaultWorkspaceId.toString();

        // --- Step 2: Initiate Login Flow ---
        const initiateRes = await request(app)
            .post("/api/v1/auth/login/initiate")
            .send({ email: testUserEmail });
        const { salt, serverPublicEphemeral, challengeKey } = initiateRes.body;

        // --- Step 3: Simulate Client-side SRP and Verify Login ---
        const clientSrpDetails = await simulateSrpClientLogin(
            testUserEmail,
            testUserPassword,
            Buffer.from(salt, "hex"),
            serverPublicEphemeral
        );

        const verifyRes = await request(app)
            .post("/api/v1/auth/login/verify")
            .send({
                challengeKey,
                clientPublicEphemeral: clientSrpDetails.clientPublicEphemeral,
                clientProof: clientSrpDetails.clientProof,
            });
        expect(verifyRes.status).toBe(200);
        userToken = verifyRes.body.token;

        // --- Step 4: Create a new Folder in the default Workspace ---
        const newFolderName = "E2E Development Folder";
        const createFolderRes = await request(app)
            .post("/api/v1/folders")
            .set("Authorization", `Bearer ${userToken}`)
            .send({
                name: newFolderName,
                workspaceId: personalWorkspaceId,
            });
        expect(createFolderRes.status).toBe(201);
        const newFolderId = createFolderRes.body.data._id;

        // --- Step 5: Create a new Item with real client-side encryption logic ---
        const itemData = {
            login: "test-login",
            password: "test-password",
            url: "https://test.com",
        };
        const itemAesKey = await generateAesKey();

        const { ciphertext: encryptedData, iv: encryptedDataIv } =
            await aesEncrypt(JSON.stringify(itemData), itemAesKey);
        const { ciphertext: encryptedRecordKey, iv: encryptedRecordKeyIv } =
            await aesKeyEncrypt(itemAesKey, userMasterKey);

        const createItemRes = await request(app)
            .post("/api/v1/items")
            .set("Authorization", `Bearer ${userToken}`)
            .send({
                folderId: newFolderId,
                type: ItemType.LOGIN,
                displayMetadata: { title: "E2E Test Login Credential" },
                encryptedData,
                encryptedDataIv,
                encryptedRecordKey,
                encryptedRecordKeyIv,
            });
        createdItemId = createItemRes.body.data._id;

        // --- Step 6: Retrieve the created Item and verify its contents (via decryption) ---
        const getItemRes = await request(app)
            .get(`/api/v1/items/${createdItemId}`)
            .set("Authorization", `Bearer ${userToken}`);

        expect(getItemRes.status).toBe(200);
        const retrievedItem = getItemRes.body.data;

        const decryptedItemKey = await aesKeyDecrypt(
            retrievedItem.encryptedRecordKey,
            userMasterKey,
            retrievedItem.encryptedRecordKeyIv
        );
        const decryptedItemDataJson = await aesDecrypt(
            retrievedItem.encryptedData,
            decryptedItemKey,
            retrievedItem.encryptedDataIv
        );
        const decryptedItemData = JSON.parse(decryptedItemDataJson);

        expect(decryptedItemData).toEqual(itemData);
    });
});

describe("End-to-End Sharing Flow with RSA", () => {
    let initiatorEmail: string;
    let initiatorPassword: string;
    let recipientEmail: string;
    let recipientPassword: string;

    let initiatorToken: string;
    let recipientToken: string;

    let initiatorRsaKeyPair: { publicKey: JsonWebKey; privateKey: JsonWebKey };
    let recipientRsaKeyPair: { publicKey: JsonWebKey; privateKey: JsonWebKey };
    let sharedItemId: string;
    let originalItemData: { username: string; password: string };
    let itemAesKey: CryptoKey | null;
    let initiatorMasterKey: CryptoKey;
    let initiatorMasterSalt: string;

    beforeEach(async () => {
        initiatorEmail = `initiator-${Date.now()}@e2e.com`;
        initiatorPassword = "InitiatorSecurePassword123";
        recipientEmail = `recipient-${Date.now()}@e2e.com`;
        recipientPassword = "RecipientSecurePassword123";

        initiatorToken = "";
        recipientToken = "";
        sharedItemId = "";
        originalItemData = {
            username: "shared_user",
            password: "shared_password_value",
        };
        itemAesKey = null;

        initiatorRsaKeyPair = await generateRsaKeyPair();
        recipientRsaKeyPair = await generateRsaKeyPair();
        initiatorMasterSalt = webcrypto
            .getRandomValues(new Uint8Array(16))
            .toString();
    });

    it("should allow an initiator to securely share an item with a recipient via RSA, and recipient can decrypt it", async () => {
        // --- Step 1: Register Initiator User (User A) ---
        const initiatorSrpSalt = await SRP.genKey(32);
        const initiatorSrpVerifier = SRP.computeVerifier(
            SRP.params[3072],
            initiatorSrpSalt,
            Buffer.from(initiatorEmail),
            Buffer.from(initiatorPassword)
        );
        initiatorMasterKey = await deriveMasterKey(
            initiatorPassword,
            initiatorMasterSalt
        );
        const {
            ciphertext: encryptedRsaPrivateKey,
            iv: encryptedRsaPrivateKeyIv,
        } = await aesEncrypt(
            JSON.stringify(initiatorRsaKeyPair.privateKey),
            initiatorMasterKey
        );
        await request(app)
            .post("/api/v1/auth/register")
            .send({
                email: initiatorEmail,
                masterSalt: initiatorMasterSalt,
                srpSalt: initiatorSrpSalt.toString("hex"),
                srpVerifier: initiatorSrpVerifier.toString("hex"),
                rsaPublicKey: JSON.stringify(initiatorRsaKeyPair.publicKey),
                encryptedRsaPrivateKey,
                encryptedRsaPrivateKeyIv,
            });
        const initiatorUser = await User.findOne({ email: initiatorEmail });
        const initiatorDefaultWorkspaceId =
            initiatorUser!.defaultWorkspaceId.toString();

        // --- Step 2: Register Recipient User (User B) ---
        const recipientSrpSalt = await SRP.genKey(32);
        const recipientSrpVerifier = SRP.computeVerifier(
            SRP.params[3072],
            recipientSrpSalt,
            Buffer.from(recipientEmail),
            Buffer.from(recipientPassword)
        );
        const recipientMasterSalt = webcrypto
            .getRandomValues(new Uint8Array(16))
            .toString();
        const recipientMasterKey = await deriveMasterKey(
            recipientPassword,
            recipientMasterSalt
        );
        const {
            ciphertext: encryptedRecipientRsaPrivateKey,
            iv: encryptedRecipientRsaPrivateKeyIv,
        } = await aesEncrypt(
            JSON.stringify(recipientRsaKeyPair.privateKey),
            recipientMasterKey
        );
        await request(app)
            .post("/api/v1/auth/register")
            .send({
                email: recipientEmail,
                masterSalt: recipientMasterSalt,
                srpSalt: recipientSrpSalt.toString("hex"),
                srpVerifier: recipientSrpVerifier.toString("hex"),
                rsaPublicKey: JSON.stringify(recipientRsaKeyPair.publicKey),
                encryptedRsaPrivateKey: encryptedRecipientRsaPrivateKey,
                encryptedRsaPrivateKeyIv: encryptedRecipientRsaPrivateKeyIv,
            });
        const recipientUser = await User.findOne({ email: recipientEmail });

        // --- Step 3: Initiator (User A) Logs In ---
        const initiatorInitiateRes = await request(app)
            .post("/api/v1/auth/login/initiate")
            .send({ email: initiatorEmail });
        const initiatorSrpDetails = await simulateSrpClientLogin(
            initiatorEmail,
            initiatorPassword,
            Buffer.from(initiatorInitiateRes.body.salt, "hex"),
            initiatorInitiateRes.body.serverPublicEphemeral
        );
        const initiatorVerifyRes = await request(app)
            .post("/api/v1/auth/login/verify")
            .send({
                challengeKey: initiatorInitiateRes.body.challengeKey,
                clientPublicEphemeral:
                    initiatorSrpDetails.clientPublicEphemeral,
                clientProof: initiatorSrpDetails.clientProof,
            });
        initiatorToken = initiatorVerifyRes.body.token;

        // --- Step 4: Initiator (User A) Creates a Folder ---
        const createFolderRes = await request(app)
            .post("/api/v1/folders")
            .set("Authorization", `Bearer ${initiatorToken}`)
            .send({
                name: "Initiator's Shared Folder",
                workspaceId: initiatorDefaultWorkspaceId,
            });
        expect(createFolderRes.status).toBe(201);
        const initiatorFolderId = createFolderRes.body.data._id;

        // --- Step 5: Initiator (User A) Creates an Item with real client-side encryption ---
        itemAesKey = await generateAesKey();
        const { ciphertext: encryptedData, iv: encryptedDataIv } =
            await aesEncrypt(JSON.stringify(originalItemData), itemAesKey);
        const { ciphertext: encryptedRecordKey, iv: encryptedRecordKeyIv } =
            await aesKeyEncrypt(itemAesKey, initiatorMasterKey);

        const createItemRes = await request(app)
            .post("/api/v1/items")
            .set("Authorization", `Bearer ${initiatorToken}`)
            .send({
                folderId: initiatorFolderId,
                type: ItemType.LOGIN,
                displayMetadata: { title: "Shared Login Item" },
                encryptedData,
                encryptedDataIv,
                encryptedRecordKey,
                encryptedRecordKeyIv,
            });
        sharedItemId = createItemRes.body.data._id;

        // --- Step 6: Initiator (User A) Shares the Item with Recipient (User B) ---
        const recipientRsaPublicKey = JSON.parse(
            recipientUser!.rsaPublicKey
        ) as JsonWebKey;
        const encryptedKeyForRecipient = await rsaEncrypt(
            itemAesKey,
            recipientRsaPublicKey
        );

        const shareRes = await request(app)
            .post("/api/v1/shares")
            .set("Authorization", `Bearer ${initiatorToken}`)
            .send({
                recipientEmail: recipientEmail,
                targetId: sharedItemId,
                targetType: ShareTargetType.ITEM,
                permissions: FolderPermissions.READ_ONLY,
                encryptedKey: encryptedKeyForRecipient,
            });
        expect(shareRes.status).toBe(201);

        // --- Step 7: Recipient (User B) Logs In ---
        const recipientInitiateRes = await request(app)
            .post("/api/v1/auth/login/initiate")
            .send({ email: recipientEmail });
        const recipientSrpDetails = await simulateSrpClientLogin(
            recipientEmail,
            recipientPassword,
            Buffer.from(recipientInitiateRes.body.salt, "hex"),
            recipientInitiateRes.body.serverPublicEphemeral
        );
        const recipientVerifyRes = await request(app)
            .post("/api/v1/auth/login/verify")
            .send({
                challengeKey: recipientInitiateRes.body.challengeKey,
                clientPublicEphemeral:
                    recipientSrpDetails.clientPublicEphemeral,
                clientProof: recipientSrpDetails.clientProof,
            });
        recipientToken = recipientVerifyRes.body.token;

        // --- Step 8: Recipient (User B) Accesses the Shared Item ---
        const getItemRes = await request(app)
            .get(`/api/v1/items/${sharedItemId}`)
            .set("Authorization", `Bearer ${recipientToken}`);
        expect(getItemRes.status).toBe(200);
        const retrievedItem = getItemRes.body.data;
        expect(retrievedItem).toHaveProperty("encryptedData");

        // --- Step 9: Recipient (User B) Decrypts the Item Data (client-side decryption simulation) ---
        const shareRecord = await Share.findOne({
            userId: recipientUser!._id,
            targetId: sharedItemId,
            targetType: ShareTargetType.ITEM,
        });
        expect(shareRecord).not.toBeNull();
        const recipientEncryptedKey = shareRecord!.encryptedKey;

        // Decrypt the item's AES key using the recipient's RSA private key
        const decryptedAesKey = await rsaDecrypt(
            recipientEncryptedKey,
            recipientRsaKeyPair.privateKey
        );

        const decryptedItemDataJson = await aesDecrypt(
            retrievedItem.encryptedData,
            decryptedAesKey,
            retrievedItem.encryptedDataIv
        );
        const decryptedItemData = JSON.parse(decryptedItemDataJson);

        expect(decryptedItemData).toEqual(originalItemData);
    });
});
