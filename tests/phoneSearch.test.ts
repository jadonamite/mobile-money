import request from "supertest";
import app from "../src/index";

describe("Phone Number Search – GET /api/transactions/search", () => {
  // ── Validation ──────────────────────────────────────────────────────────

  it("should return 400 when phoneNumber param is missing", async () => {
    const res = await request(app).get("/api/transactions/search");
    expect(res.status).toBe(400);
    expect(res.body.error).toContain("phoneNumber");
  });

  it("should return 400 for invalid phone number (letters)", async () => {
    const res = await request(app).get(
      "/api/transactions/search?phoneNumber=abc123",
    );
    expect(res.status).toBe(400);
    expect(res.body.error).toContain("Invalid phone number format");
  });

  it("should return 400 for empty phone number", async () => {
    const res = await request(app).get(
      "/api/transactions/search?phoneNumber=",
    );
    expect(res.status).toBe(400);
    expect(res.body.error).toContain("phoneNumber");
  });

  it("should return 400 for phone number with special characters", async () => {
    const res = await request(app).get(
      "/api/transactions/search?phoneNumber=123-456-7890",
    );
    expect(res.status).toBe(400);
    expect(res.body.error).toContain("Invalid phone number format");
  });

  // ── Successful Requests ─────────────────────────────────────────────────

  it("should return 200 with pagination for a valid full phone number", async () => {
    const res = await request(app).get(
      "/api/transactions/search?phoneNumber=%2B237612345678",
    );
    expect(res.status).toBe(200);
    expect(res.body.success).toBe(true);
    expect(res.body.pagination).toHaveProperty("page");
    expect(res.body.pagination).toHaveProperty("limit");
    expect(res.body.pagination).toHaveProperty("total");
    expect(res.body.pagination).toHaveProperty("totalPages");
    expect(Array.isArray(res.body.data)).toBe(true);
  });

  it("should return 200 for partial phone number (last 4 digits)", async () => {
    const res = await request(app).get(
      "/api/transactions/search?phoneNumber=5678",
    );
    expect(res.status).toBe(200);
    expect(res.body.success).toBe(true);
    expect(Array.isArray(res.body.data)).toBe(true);
  });

  it("should accept a phone number with leading +", async () => {
    const res = await request(app).get(
      "/api/transactions/search?phoneNumber=%2B2376",
    );
    expect(res.status).toBe(200);
    expect(res.body.success).toBe(true);
  });

  // ── Privacy / Masking ───────────────────────────────────────────────────

  it("should mask phone numbers in the response (only last 4 digits visible)", async () => {
    const res = await request(app).get(
      "/api/transactions/search?phoneNumber=1234",
    );
    expect(res.status).toBe(200);

    // If results exist, every phone_number must be masked
    for (const tx of res.body.data) {
      if (tx.phone_number) {
        expect(tx.phone_number).toMatch(/^\*{4}\d{4}$/);
      }
    }
  });

  // ── Pagination ──────────────────────────────────────────────────────────

  it("should respect page and limit query params", async () => {
    const res = await request(app).get(
      "/api/transactions/search?phoneNumber=1234&page=2&limit=5",
    );
    expect(res.status).toBe(200);
    expect(res.body.pagination.page).toBe(2);
    expect(res.body.pagination.limit).toBe(5);
  });

  it("should default to page 1 and limit 50", async () => {
    const res = await request(app).get(
      "/api/transactions/search?phoneNumber=1234",
    );
    expect(res.status).toBe(200);
    expect(res.body.pagination.page).toBe(1);
    expect(res.body.pagination.limit).toBe(50);
  });

  it("should cap limit at 100", async () => {
    const res = await request(app).get(
      "/api/transactions/search?phoneNumber=1234&limit=999",
    );
    expect(res.status).toBe(200);
    expect(res.body.pagination.limit).toBeLessThanOrEqual(100);
  });
});
