import * as StellarSdk from "stellar-sdk";
import { getStellarServer, getNetworkPassphrase } from "../../config/stellar";
import dotenv from "dotenv";
import { transactionTotal, transactionErrorsTotal } from "../../utils/metrics";

dotenv.config();

export class StellarService {
  private server: StellarSdk.Horizon.Server;
  private issuerKeypair: StellarSdk.Keypair | null = null;
  private isMockMode: boolean = false;

  constructor() {
    this.server = getStellarServer();

    const secret = process.env.STELLAR_ISSUER_SECRET;

    if (!secret) {
      console.warn("⚠️ STELLAR_ISSUER_SECRET not set - running in MOCK mode");
      this.isMockMode = true;
    } else {
      this.issuerKeypair = StellarSdk.Keypair.fromSecret(secret);
    }
  }

  async sendPayment(destinationAddress: string, amount: string): Promise<void> {
    try {
      // ✅ MOCK MODE (no crash)
      if (this.isMockMode || !this.issuerKeypair) {
        console.log("🚀 Mock Stellar payment:", {
          to: destinationAddress,
          amount,
        });

        transactionTotal.inc({
          type: "stellar_payment",
          provider: "stellar",
          status: "success",
        });

        return;
      }

      // ✅ REAL MODE
      const account = await this.server.loadAccount(
        this.issuerKeypair.publicKey()
      );

      const transaction = new StellarSdk.TransactionBuilder(account, {
        fee: StellarSdk.BASE_FEE,
        networkPassphrase: getNetworkPassphrase(),
      })
        .addOperation(
          StellarSdk.Operation.payment({
            destination: destinationAddress,
            asset: StellarSdk.Asset.native(),
            amount: amount,
          })
        )
        .setTimeout(30)
        .build();

      transaction.sign(this.issuerKeypair);
      await this.server.submitTransaction(transaction);

      transactionTotal.inc({
        type: "stellar_payment",
        provider: "stellar",
        status: "success",
      });
    } catch (error) {
      transactionTotal.inc({
        type: "stellar_payment",
        provider: "stellar",
        status: "failure",
      });

      transactionErrorsTotal.inc({
        type: "stellar_payment",
        provider: "stellar",
        error_type: "stellar_error",
      });

      throw error;
    }
  }

  async getBalance(address: string): Promise<string> {
    try {
      // ✅ MOCK MODE
      if (this.isMockMode) {
        console.log("💰 Mock balance check for:", address);
        return "1000"; // fake balance
      }

      const account = await this.server.loadAccount(address);
      const balance = account.balances.find(
        (b) => b.asset_type === "native"
      );

      return balance ? balance.balance : "0";
    } catch (error) {
      console.error("Balance fetch failed", error);
      return "0";
    }
  }
}