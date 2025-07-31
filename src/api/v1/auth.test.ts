import request from "supertest";
import app from "../../server";

jest.mock("../../config/db");

describe("Auth Routes /api/v1/auth", () => {
    describe("POST /register", () => {
        const testUser = {
            email: "test@example.com",
            srpSalt: "somesalt",
            srpVerifier: "someverifier",
            rsaPublicKey: "somekey",
        };

        it("should register a new user successfully and return status 201", async () => {
            const res = await request(app)
                .post("/api/v1/auth/register")
                .send(testUser);

            expect(res.status).toBe(201);
            expect(res.body.user).toHaveProperty("email", testUser.email);
        });

        it("should fail with status 409 if email already exists", async () => {
            await request(app).post("/api/v1/auth/register").send(testUser);

            const res = await request(app)
                .post("/api/v1/auth/register")
                .send(testUser);

            expect(res.status).toBe(409);
            expect(res.body).toHaveProperty(
                "message",
                "Cannot register user: Email already exists"
            );
        });

        it("should fail with status 400 if required fields are missing", async () => {
            const res = await request(app)
                .post("/api/v1/auth/register")
                .send({ email: "test@example.com" });

            expect(res.status).toBe(400);
            expect(res.body).toHaveProperty(
                "message",
                "Please provide all information."
            );
        });
    });

    // We can add tests for /login/initiate and /login/verify later.
    // Those are more complex as they require simulating the client-side SRP calculations.
});
