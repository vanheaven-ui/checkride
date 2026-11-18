import { describe, expect, it } from "vitest";
import { supabaseCheck } from "@/lib/scanner/checks/site/supabase";
import { redactSecret } from "@/lib/scanner/redact";
import { makeContext } from "../../helpers/snapshot";

const PROJECT = "abcdefghijklmnopqrst";
const PROJECT_URL = `https://${PROJECT}.supabase.co`;

function b64url(value: string): string {
  return Buffer.from(value, "utf8").toString("base64url");
}

function fakeJwt(payload: Record<string, unknown>): string {
  return `${b64url('{"alg":"HS256","typ":"JWT"}')}.${b64url(JSON.stringify(payload))}.${b64url("sig")}`;
}

const SERVICE_JWT = fakeJwt({ role: "service_role", iss: `${PROJECT_URL}/auth/v1` });
const ANON_JWT = fakeJwt({ role: "anon", iss: `${PROJECT_URL}/auth/v1` });
const MALFORMED_JWT = `${b64url("h")}.${b64url("not json at all")}.${b64url("s")}`;

function script(url: string, body: string) {
  return { url, body, truncated: false };
}

describe("site.backend.supabase", () => {
  it("flags a service_role JWT as critical/high with the token redacted", async () => {
    const ctx = makeContext({
      scripts: [script("https://example.com/app.js", `jwt="${SERVICE_JWT}";`)],
    });
    const findings = await supabaseCheck.run(ctx);
    expect(findings).toHaveLength(1);
    expect(findings[0]).toMatchObject({
      checkId: "site.backend.supabase",
      severity: "critical",
      confidence: "high",
      title: "A Supabase service role key appears in public code",
      location: "https://example.com/app.js",
    });
    expect(findings[0].evidence).toContain(redactSecret(SERVICE_JWT));
    expect(JSON.stringify(findings)).not.toContain(SERVICE_JWT);
  });

  it("flags project URL + anon JWT as info/high mentioning RLS", async () => {
    const ctx = makeContext({
      scripts: [script("https://example.com/app.js", `url="${PROJECT_URL}"; anon="${ANON_JWT}";`)],
    });
    const findings = await supabaseCheck.run(ctx);
    expect(findings).toHaveLength(1);
    expect(findings[0]).toMatchObject({
      severity: "info",
      confidence: "high",
      title: "Supabase detected: confirm Row Level Security is enabled on every table",
    });
    expect(findings[0].evidence).toContain("Row Level Security cannot be verified");
    expect(findings[0].evidence).toContain(PROJECT_URL);
    expect(JSON.stringify(findings)).not.toContain(ANON_JWT);
  });

  it("emits both findings when service_role and anon credentials are present", async () => {
    const ctx = makeContext({
      scripts: [
        script(
          "https://example.com/app.js",
          `url="${PROJECT_URL}"; svc="${SERVICE_JWT}"; anon="${ANON_JWT}";`,
        ),
      ],
    });
    const findings = await supabaseCheck.run(ctx);
    expect(findings.map((f) => f.severity).sort()).toEqual(["critical", "info"]);
  });

  it("requires a project URL for the anon finding", async () => {
    const ctx = makeContext({
      scripts: [script("https://example.com/app.js", `anon="${ANON_JWT}";`)],
    });
    expect(await supabaseCheck.run(ctx)).toEqual([]);
  });

  it("ignores malformed JWTs and non-supabase content", async () => {
    const ctx = makeContext({
      html: `<html><body>nothing here "${MALFORMED_JWT}"</body></html>`,
      scripts: [script("https://example.com/app.js", `jwt="${MALFORMED_JWT}"; v=1.2.3;`)],
    });
    expect(await supabaseCheck.run(ctx)).toEqual([]);
  });

  it("finds credentials in the HTML too", async () => {
    const ctx = makeContext({
      finalUrl: "https://example.com/",
      html: `<script>var t="${SERVICE_JWT}";</script>`,
    });
    const findings = await supabaseCheck.run(ctx);
    expect(findings).toHaveLength(1);
    expect(findings[0].severity).toBe("critical");
    expect(findings[0].location).toBe("https://example.com/");
  });

  it("de-duplicates the same token across html and scripts", async () => {
    const ctx = makeContext({
      html: `<script>var t="${SERVICE_JWT}";</script>`,
      scripts: [script("https://example.com/a.js", `t="${SERVICE_JWT}";`)],
    });
    const findings = await supabaseCheck.run(ctx);
    expect(findings).toHaveLength(1);
    expect(findings[0].evidence).not.toContain("2 tokens");
  });
});
