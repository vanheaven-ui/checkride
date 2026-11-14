import { describe, expect, it } from "vitest";
import { frameCheck } from "@/lib/scanner/checks/site/frame";
import { makeContext } from "../../helpers/snapshot";

describe("site.headers.frame", () => {
  it.each(["DENY", "SAMEORIGIN", "deny", "sameorigin"])(
    "returns nothing when X-Frame-Options is %s",
    async (value) => {
      const findings = await frameCheck.run(makeContext({ headers: { "x-frame-options": value } }));
      expect(findings).toEqual([]);
    },
  );

  it("returns nothing when the CSP has frame-ancestors", async () => {
    const findings = await frameCheck.run(
      makeContext({
        headers: {
          "content-security-policy": "default-src 'self'; frame-ancestors 'none'",
        },
      }),
    );
    expect(findings).toEqual([]);
  });

  it("flags a page with neither protection on https and http", async () => {
    for (const finalUrl of ["https://example.com/", "http://example.com/"]) {
      const findings = await frameCheck.run(makeContext({ finalUrl, requestedUrl: finalUrl }));
      expect(findings).toHaveLength(1);
      expect(findings[0]).toMatchObject({
        checkId: "site.headers.frame",
        severity: "low",
        confidence: "high",
        title: "Page can be embedded in other sites (clickjacking risk)",
        evidence: "header not present",
      });
    }
  });

  it("flags an unrecognized X-Frame-Options value", async () => {
    const findings = await frameCheck.run(
      makeContext({ headers: { "x-frame-options": "ALLOWALL" } }),
    );
    expect(findings).toHaveLength(1);
    expect(findings[0]?.evidence).toBe("ALLOWALL");
  });
});
