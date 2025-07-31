import { Request } from "express";

interface IUserPayload {
    userId: string;
    email: string;
}

declare global {
    namespace Express {
        export interface Request {
            user?: IUserPayload;
        }
    }
}
