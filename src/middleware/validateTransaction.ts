import { Request, Response, NextFunction } from "express";
import { z } from "zod";

const transactionSchema = z.object({
  amount: z.number().positive({ message: "Amount must be a positive number" }),
  phoneNumber: z.string().regex(/^\+?\d{10,15}$/, { message: "Invalid phone number format" }),
  provider: z.enum(["mtn", "airtel", "orange"], { message: "Provider must be one of: mtn, airtel, orange" }),
  stellarAddress: z.string().regex(/^G[A-Z2-7]{55}$/, { message: "Invalid Stellar address format" }),
  userId: z.string().nonempty({ message: "userId is required" }),
});

export const validateTransaction = (req: Request, res: Response, next: NextFunction) => {
  try {
    transactionSchema.parse(req.body);
    next();
  } catch (err: any) {
    console.log("Validation error:", err.errors); // 👈 ADD THIS

    return res.status(400).json({
      error: "Validation failed",
      details: err.errors, // 👈 SHOW REAL ERROR
    });
  }
};