import { describe, expect, it } from "vitest";
import { cspCheck } from "@/lib/scanner/checks/site/csp";
import { makeContext } from "../../helpers/snapshot";

describe("site.headers.csp", () => {
  it("flags a missing CSP header", async () => {
    const findings = await cspCheck.run(makeContext());
    expect(findings).toHaveLength(1);
    expect(findings[0]).toMatchObject({
      checkId: "site.headers.csp",
      severity: "medium",
      confidence: "high",
      title: "No Content-Security-Policy header",
      evidence: "header not present",
    });
  });

  it("flags a report-only CSP as low severity", async () => {
    const findings = await cspCheck.run(
      makeContext({
        headers: {
          "content-security-policy-report-only": "default-src 'self'",
        },
      }),
    );
    expect(findings).toHaveLength(1);
    expect(findings[0]).toMatchObject({
      severity: "low",
      confidence: "high",
      title: "CSP is report-only",
    });
  });

  it("flags unsafe-inline in script-src", async () => {
    const findings = await cspCheck.run(
      makeContext({
        headers: {
          "content-security-policy": "default-src 'self'; script-src 'self' 'unsafe-inline'",
        },
      }),
    );
    expect(findings).toHaveLength(1);
    expect(findings[0]).toMatchObject({
      severity: "low",
      confidence: "medium",
      title: "CSP allows unsafe script execution",
    });
  });

  it("ignores unsafe-inline when a nonce, hash, or strict-dynamic is present", async () => {
    for (const csp of [
      "script-src 'self' 'unsafe-inline' 'nonce-abc123'",
      "script-src 'self' 'unsafe-inline' 'sha256-deadbeef'",
      "script-src 'self' 'unsafe-inline' 'strict-dynamic'",
    ]) {
      const findings = await cspCheck.run(
        makeContext({ headers: { "content-security-policy": csp } }),
      );
      expect(findings).toEqual([]);
    }
  });

  it("always flags unsafe-eval even with a nonce present", async () => {
    const findings = await cspCheck.run(
      makeContext({
        headers: {
          "content-security-policy": "script-src 'self' 'unsafe-eval' 'nonce-abc'",
        },
      }),
    );
    expect(findings).toHaveLength(1);
    expect(findings[0]?.title).toBe("CSP allows unsafe script execution");
  });

  it("falls back to default-src when script-src is absent", async () => {
    const findings = await cspCheck.run(
      makeContext({
        headers: { "content-security-policy": "default-src 'self' 'unsafe-inline'" },
      }),
    );
    expect(findings).toHaveLength(1);
  });

  it("returns nothing for a reasonable CSP on http and https", async () => {
    const csp = "default-src 'self'; script-src 'self'; frame-ancestors 'none'";
    for (const finalUrl of ["https://example.com/", "http://example.com/"]) {
      const findings = await cspCheck.run(
        makeContext({
          finalUrl,
          requestedUrl: finalUrl,
          headers: { "content-security-policy": csp },
        }),
      );
      expect(findings).toEqual([]);
    }
  });
  it("does not excuse unsafe-inline because of a nonce in another directive", async () => {
    const findings = await cspCheck.run(
      makeContext({
        headers: {
          "content-security-policy":
            "script-src 'self' 'unsafe-inline'; style-src 'self' 'nonce-abc123'",
        },
      }),
    );
    expect(findings).toHaveLength(1);
    expect(findings[0]?.title).toBe("CSP allows unsafe script execution");
  });
});
