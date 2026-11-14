import { describe, expect, it } from "vitest";
import { cookiesCheck } from "@/lib/scanner/checks/site/cookies";
import { makeContext } from "../../helpers/snapshot";

const HTTPS = "https://example.com/";
const HTTP = "http://example.com/";

function ctxWithCookies(cookies: string[] | undefined, finalUrl = HTTPS) {
  return makeContext({
    finalUrl,
    requestedUrl: finalUrl,
    headers: cookies === undefined ? {} : { "set-cookie": cookies },
  });
}

function allFields(findings: { evidence: string; title: string }[]): string {
  return JSON.stringify(findings);
}

describe("site.cookies", () => {
  it("returns nothing when the header is missing or empty", async () => {
    expect(await cookiesCheck.run(ctxWithCookies(undefined))).toEqual([]);
    expect(await cookiesCheck.run(ctxWithCookies([]))).toEqual([]);
  });

  it("groups issues by type with one finding each", async () => {
    const findings = await cookiesCheck.run(
      ctxWithCookies(
        [
          "session=SECRETVALUE123; Path=/",
          "theme=abc; Path=/; HttpOnly; SameSite=Lax; Secure",
          "prefs=SECRETVALUE123; Path=/; HttpOnly", // missing SameSite only
        ],
        HTTPS,
      ),
    );

    const byTitle = new Map(findings.map((f) => [f.title, f]));

    // session cookie: no flags at all on https -> Secure + HttpOnly(sensitive) + SameSite
    expect(byTitle.get("Cookies missing the Secure flag on an HTTPS page")).toMatchObject({
      severity: "medium",
      confidence: "high",
    });
    expect(byTitle.get("Session-like cookies missing the HttpOnly flag")).toMatchObject({
      severity: "medium",
      confidence: "medium",
    });
    expect(byTitle.get("Cookies missing the SameSite attribute")).toMatchObject({
      severity: "low",
      confidence: "medium",
    });
    // prefs is missing SameSite too, so it joins that group; theme is clean.
    const sameSite = byTitle.get("Cookies missing the SameSite attribute");
    expect(sameSite?.evidence).toContain("session");
    expect(sameSite?.evidence).toContain("prefs");
    expect(sameSite?.evidence).not.toContain("theme");
  });

  it("flags SameSite=None without Secure at medium/high", async () => {
    const findings = await cookiesCheck.run(
      ctxWithCookies(["tracker=SECRETVALUE123; Path=/; SameSite=None; HttpOnly; Secure"]),
    );
    // Secure present -> no Secure finding; SameSite=None + Secure -> no issue there either.
    expect(findings).toEqual([]);

    const findings2 = await cookiesCheck.run(
      ctxWithCookies(["tracker=SECRETVALUE123; Path=/; SameSite=None"]),
    );
    const noneFinding = findings2.find((f) => f.title.includes("SameSite=None"));
    expect(noneFinding).toMatchObject({ severity: "medium", confidence: "high" });
  });

  it("treats attribute parsing case-insensitively and tolerates '=' in values", async () => {
    const findings = await cookiesCheck.run(
      ctxWithCookies(["jwt=abc=def==; Path=/; HTTPONLY; samesite=Strict; SECURE"]),
    );
    expect(findings).toEqual([]);
  });

  it("skips the Secure check on plain HTTP pages", async () => {
    const findings = await cookiesCheck.run(
      ctxWithCookies(["session=SECRETVALUE123; Path=/; HttpOnly; SameSite=Lax"], HTTP),
    );
    expect(findings.find((f) => f.title.includes("Secure flag"))).toBeUndefined();
  });

  it("caps the cookie name list at 5 with an overflow count", async () => {
    const cookies = Array.from(
      { length: 7 },
      (_, i) => `c${i}=SECRETVALUE123; Path=/; HttpOnly; SameSite=Lax; Secure`,
    );
    const findings = await cookiesCheck.run(ctxWithCookies(cookies));
    // All cookies are missing nothing except... they have all flags -> no findings.
    // Use cookies missing SameSite instead:
    const noSameSite = cookies.map((c) => c.replace("; SameSite=Lax", ""));
    const findings2 = await cookiesCheck.run(ctxWithCookies(noSameSite));
    const f = findings2.find((x) => x.title.includes("SameSite"));
    expect(f?.evidence).toContain("(+2 more)");
    expect(f?.evidence).not.toContain("c6");
    expect(findings).toEqual([]);
  });

  it("never includes cookie values in any finding field", async () => {
    const findings = await cookiesCheck.run(
      ctxWithCookies(
        [
          "session=SECRETVALUE123; Path=/",
          "auth_token=SECRETVALUE123; Path=/; SameSite=None",
          "prefs=SECRETVALUE123; Path=/",
        ],
        HTTPS,
      ),
    );
    expect(findings.length).toBeGreaterThan(0);
    expect(allFields(findings)).not.toContain("SECRETVALUE123");
    for (const f of findings) {
      expect(f.evidence).toContain("Cookie names:");
    }
  });
});
