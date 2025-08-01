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

// This empty export is required to turn this file into a module.
// This is necessary for the 'declare global' block to correctly augment
// the existing 'Express.Request' interface from the @types/express module.
export {};
