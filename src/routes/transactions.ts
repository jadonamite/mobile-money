import { Router } from "express";
import {
  depositHandler,
  withdrawHandler,
  getTransactionHandler,
  cancelTransactionHandler,
  validateTransaction,
} from "../controllers/transactionController";
import { TimeoutPresets, haltOnTimedout } from "../middleware/timeout";

export const transactionRoutes = Router();

// Deposit route
transactionRoutes.post(
  "/deposit",
  TimeoutPresets.long,
  haltOnTimedout,
  validateTransaction,
  depositHandler
);

// Withdraw route
transactionRoutes.post(
  "/withdraw",
  TimeoutPresets.long,
  haltOnTimedout,
  validateTransaction,
  withdrawHandler
);

// Get transaction
transactionRoutes.get("/:id", TimeoutPresets.quick, haltOnTimedout, getTransactionHandler);

// Cancel transaction
transactionRoutes.post("/:id/cancel", TimeoutPresets.quick, haltOnTimedout, cancelTransactionHandler);