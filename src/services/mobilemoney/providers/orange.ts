import axios, { AxiosInstance } from "axios";

export class OrangeProvider {
  private client: AxiosInstance;
  private token: string | null = null;
  private tokenExpiry = 0;

  constructor() {
    this.client = axios.create({
      baseURL: process.env.ORANGE_BASE_URL || "https://sandbox.orange.com",
      timeout: Number(process.env.REQUEST_TIMEOUT_MS || 10000),
    });
  }

  private async authenticate(): Promise<string> {
    if (this.token && Date.now() < this.tokenExpiry) return this.token;

    const clientId = process.env.ORANGE_API_KEY || "";
    const clientSecret = process.env.ORANGE_API_SECRET || "";

    try {
      const authHeader =
        "Basic " + Buffer.from(`${clientId}:${clientSecret}`).toString("base64");

      // Many Orange APIs accept client_credentials grant as form data
      const resp = await this.client.post(
        "/oauth/token",
        "grant_type=client_credentials",
        {
          headers: {
            Authorization: authHeader,
            "Content-Type": "application/x-www-form-urlencoded",
          },
        }
      );

      const data = resp.data;
      this.token = data.access_token;
      // expires_in is seconds
      this.tokenExpiry = Date.now() + (data.expires_in || 3600) * 1000 - 5000; // small skew

      return this.token!;
    } catch (err) {
      console.error("Orange auth failed", (err as any)?.response?.data || err);
      throw new Error("Orange authentication failed");
    }
  }

  private async withRetry<T>(fn: () => Promise<T>, retries = 3): Promise<T> {
    let lastErr: any;

    for (let i = 0; i < retries; i++) {
      try {
        return await fn();
      } catch (err) {
        lastErr = err;

        const status = (err as any)?.response?.status;
        const code = (err as any)?.code;

        // Retry on 5xx or network/timeouts
        if ((status && status >= 500) || code === "ECONNABORTED" || code === "ECONNRESET") {
          const backoff = 1000 * (i + 1);
          console.warn(`Orange request failed, retry ${i + 1} after ${backoff}ms`);
          await new Promise((r) => setTimeout(r, backoff));
          continue;
        }

        // Do not retry for client errors
        break;
      }
    }

    throw lastErr;
  }

  /**
   * Request a payment (collection) from a subscriber
   */
  async requestPayment(phoneNumber: string, amount: string | number) {
    const token = await this.authenticate();
    const reference = `ORANGE-PAY-${Date.now()}`;

    try {
      const result = await this.withRetry(async () => {
        const response = await this.client.post(
          "/v1/payments/collect",
          {
            reference,
            subscriber: {
              msisdn: phoneNumber,
            },
            transaction: {
              amount: parseFloat(String(amount)),
              currency: process.env.ORANGE_CURRENCY || "XAF",
              id: reference,
            },
          },
          {
            headers: {
              Authorization: `Bearer ${token}`,
              "Content-Type": "application/json",
            },
          }
        );

        return { success: true, data: response.data, reference };
      });

      return result;
    } catch (error) {
      return { success: false, error };
    }
  }

  /**
   * Check payment/disbursement status by reference
   */
  async checkStatus(reference: string) {
    const token = await this.authenticate();

    return this.withRetry(async () => {
      const response = await this.client.get(`/v1/payments/${encodeURIComponent(reference)}`, {
        headers: { Authorization: `Bearer ${token}` },
      });

      return { success: true, data: response.data };
    });
  }

  /**
   * Send a payout (disbursement) to a subscriber
   */
  async sendPayout(phoneNumber: string, amount: string | number) {
    const token = await this.authenticate();
    const reference = `ORANGE-PAYOUT-${Date.now()}`;

    try {
      const result = await this.withRetry(async () => {
        const response = await this.client.post(
          "/v1/payments/disburse",
          {
            reference,
            payee: { msisdn: phoneNumber },
            transaction: {
              amount: parseFloat(String(amount)),
              currency: process.env.ORANGE_CURRENCY || "XAF",
              id: reference,
            },
          },
          {
            headers: {
              Authorization: `Bearer ${token}`,
              "Content-Type": "application/json",
            },
          }
        );

        return { success: true, data: response.data, reference };
      });

      return result;
    } catch (error) {
      return { success: false, error };
    }
  }
}
