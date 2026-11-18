import { describe, expect, it } from "vitest";
import { bundleSecretsCheck } from "@/lib/scanner/checks/site/bundle-secrets";
import { redactSecret } from "@/lib/scanner/redact";
import { makeContext } from "../../helpers/snapshot";

const STRIPE_LIVE = "sk" + "_live_" + "x".repeat(24);
const AWS_KEY = "AKIA" + "QWERTYUIOPASDFGH";

function script(url: string, body: string, truncated = false) {
  return { url, body, truncated };
}

describe("site.bundle.secrets", () => {
  it("finds a secret in a script and reports the path-only location", async () => {
    const ctx = makeContext({
      scripts: [
        script(
          "https://example.com/static/app.js?v=123#frag",
          `var k="${STRIPE_LIVE}";console.log(k);`,
        ),
      ],
    });
    const findings = await bundleSecretsCheck.run(ctx);
    expect(findings).toHaveLength(1);
    expect(findings[0]).toMatchObject({
      checkId: "site.bundle.secrets",
      severity: "critical",
      confidence: "high",
      location: "https://example.com/static/app.js",
    });
    expect(findings[0].title).toBe("Stripe live secret key found in public code");
    expect(findings[0].evidence).toContain(redactSecret(STRIPE_LIVE));
    expect(findings[0].evidence).toContain("at character");
    expect(JSON.stringify(findings)).not.toContain(STRIPE_LIVE);
  });

  it("uses 'Possible' wording for non-high confidence matches", async () => {
    const ctx = makeContext({
      scripts: [script("https://example.com/a.js", `aws="${AWS_KEY}";`)],
    });
    const findings = await bundleSecretsCheck.run(ctx);
    expect(findings).toHaveLength(1);
    expect(findings[0].confidence).toBe("medium");
    expect(findings[0].title).toMatch(/^Possible /);
  });

  it("scans the HTML as well and uses the page location", async () => {
    const ctx = makeContext({
      finalUrl: "https://example.com/index.html?x=1",
      html: `<html><body><script>var k="${STRIPE_LIVE}";</script></body></html>`,
    });
    const findings = await bundleSecretsCheck.run(ctx);
    expect(findings).toHaveLength(1);
    expect(findings[0].location).toBe("https://example.com/index.html");
  });

  it("finds secrets in minified single-line bundles", async () => {
    const ctx = makeContext({
      scripts: [
        script(
          "https://example.com/bundle.min.js",
          `!function(){var e="${STRIPE_LIVE}",t=[1,2,3];console.log(e,t)}();`,
        ),
      ],
    });
    const findings = await bundleSecretsCheck.run(ctx);
    expect(findings.map((f) => f.severity)).toContain("critical");
  });

  it("does not flag publishable keys or placeholder values", async () => {
    const ctx = makeContext({
      scripts: [
        script(
          "https://example.com/app.js",
          `var pk="pk_live_"+"P".repeat(24);var s={apiSecret:"your-key-here-change-me-please-ok"};`,
        ),
      ],
    });
    expect(await bundleSecretsCheck.run(ctx)).toEqual([]);
  });

  it("de-duplicates identical secrets within one script", async () => {
    const ctx = makeContext({
      scripts: [script("https://example.com/app.js", `a="${STRIPE_LIVE}";b="${STRIPE_LIVE}";`)],
    });
    const findings = await bundleSecretsCheck.run(ctx);
    expect(findings).toHaveLength(1);
  });

  it("caps findings at 20", async () => {
    // Build 25 distinct live keys at runtime and serve them assembled.
    const body = Array.from({ length: 25 }, (_, i) => {
      const key = "sk" + "_live_" + "K" + i.toString(36).padStart(2, "0") + "x".repeat(20);
      return `k${i}="${key}";`;
    }).join("");
    const ctx = makeContext({ scripts: [script("https://example.com/big.js", body)] });
    const findings = await bundleSecretsCheck.run(ctx);
    expect(findings.length).toBeLessThanOrEqual(20);
    expect(findings.length).toBe(20);
  });

  it("reports an info finding when the text budget leaves scripts unscanned", async () => {
    // HTML alone exhausts the 10M-char budget, so every script is skipped.
    const ctx = makeContext({
      html: "a".repeat(10 * 1024 * 1024),
      scripts: [
        script("https://example.com/a.js", `k="${STRIPE_LIVE}";`),
        script("https://example.com/b.js", "console.log(1);"),
      ],
    });
    const findings = await bundleSecretsCheck.run(ctx);
    const note = findings.find((f) => f.severity === "info");
    expect(note).toMatchObject({
      checkId: "site.bundle.secrets",
      title: "Not all scripts could be scanned for secrets",
    });
    expect(note?.evidence).toContain("2 script file(s)");
    // The secret in the skipped scripts must not be reported.
    expect(JSON.stringify(findings)).not.toContain(STRIPE_LIVE);
  });

  it("still scans a partially-covered script up to the budget", async () => {
    const bigScript = "a".repeat(10 * 1024 * 1024) + `k="${STRIPE_LIVE}";`;
    const ctx = makeContext({
      html: "<html></html>",
      scripts: [script("https://example.com/big.js", bigScript)],
    });
    const findings = await bundleSecretsCheck.run(ctx);
    // The key sits beyond the 10M budget, so it is not found and no script is
    // reported fully unscanned (the first script was partially scanned).
    expect(findings.filter((f) => f.severity !== "info")).toEqual([]);
  });
});
