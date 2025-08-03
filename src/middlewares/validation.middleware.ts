import { Request, Response, NextFunction } from "express";
import z, { ZodObject, ZodError } from "zod";

export const mongoIdSchema = z
    .string()
    .regex(/^[0-9a-fA-F]{24}$/, "Invalid ID format");

export const validateRequest =
    (schema: ZodObject) =>
    (req: Request, res: Response, next: NextFunction) => {
        try {
            schema.parse({
                body: req.body,
                query: req.query,
                params: req.params,
            });
            next();
        } catch (error) {
            if (error instanceof ZodError) {
                const firstIssue = error.issues[0];
                return res.status(400).json({
                    message: firstIssue.message,
                    errors: error.issues,
                });
            }
            next(error);
        }
    };
