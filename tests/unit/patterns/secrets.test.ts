import { describe, expect, it } from "vitest";
import {
  decodeJwtPayload,
  findJwts,
  findSecrets,
  SECRET_PATTERNS,
} from "@/lib/scanner/patterns/secrets";

// All fake values are assembled at runtime so no secret-shaped literal
// exists in the repo.
const STRIPE_LIVE = "sk" + "_live_" + "A1b2C3d4E5f6G7h8I9j0Kl";
const STRIPE_TEST = "rk" + "_test_" + "T3stV4lu3T3stV4lu3T3st";
const AWS_KEY = "AKIA" + "QWERTYUIOPASDFGH";
const GITHUB_TOKEN = "ghp_" + "aB3dE5fG7hI9jK1lM3nO5p";
const SLACK_TOKEN = "xoxb-" + "123456789012-abcdefghijkl";
const ANTHROPIC_KEY = "sk-ant-" + "api03-" + "xY9zW8vU7tS6rQ5pN4mL";
const OPENAI_STYLE = "sk-" + "proj-Ab3dE5fG7hI9jK1lM3nO";
const HIGH_ENTROPY_VALUE = "V7kQ2mX9pL4wR8tY3uI6oP1sD5fG0hJ2";

function b64url(value: string): string {
  return Buffer.from(value, "utf8").toString("base64url");
}

function fakeJwt(payload: Record<string, unknown>): string {
  return `${b64url('{"alg":"HS256","typ":"JWT"}')}.${b64url(JSON.stringify(payload))}.${b64url("sig")}`;
}

function patternIds(text: string): string[] {
  return findSecrets(text).map((m) => m.patternId);
}

describe("findSecrets", () => {
  it("flags Stripe live and restricted keys as critical/high", () => {
    const matches = findSecrets(`const k = "${STRIPE_LIVE}";`);
    expect(matches).toHaveLength(1);
    expect(matches[0]).toMatchObject({
      patternId: "stripe-live",
      severity: "critical",
      confidence: "high",
      value: STRIPE_LIVE,
    });
  });

  it("flags Stripe test keys as medium/high", () => {
    const matches = findSecrets(`key: '${STRIPE_TEST}'`);
    expect(matches).toHaveLength(1);
    expect(matches[0]).toMatchObject({
      patternId: "stripe-test",
      severity: "medium",
      confidence: "high",
    });
  });

  it("does not flag Stripe publishable keys", () => {
    const pk = "pk" + "_live_" + "P1bl1cK3yV4lu3P1bl1cK3y";
    expect(findSecrets(`const pk = "${pk}";`)).toEqual([]);
  });

  it("flags AWS access key IDs but not the documented example", () => {
    const matches = findSecrets(`aws_key = ${AWS_KEY}`);
    expect(matches).toHaveLength(1);
    expect(matches[0]).toMatchObject({
      patternId: "aws-access-key",
      severity: "critical",
      confidence: "medium",
    });
    expect(findSecrets("AKIAIOSFODNN7EXAMPLE")).toEqual([]);
  });

  it("flags private key block markers", () => {
    for (const marker of [
      "-----BEGIN PRIVATE KEY-----",
      "-----BEGIN RSA PRIVATE KEY-----",
      "-----BEGIN OPENSSH PRIVATE KEY-----",
    ]) {
      const matches = findSecrets(marker);
      expect(matches.map((m) => m.patternId)).toContain("private-key-block");
    }
    expect(findSecrets("-----BEGIN CERTIFICATE-----")).toEqual([]);
  });

  it("flags GitHub tokens including fine-grained github_pat_", () => {
    expect(patternIds(`t = "${GITHUB_TOKEN}"`)).toContain("github-token");
    const pat = "github_pat_" + "11ABCDEFG0_" + "zZ9yY8xX7wW6vV5uU4tT3sS2rR1qQ0pP";
    expect(patternIds(`t = "${pat}"`)).toContain("github-token");
  });

  it("flags Slack tokens", () => {
    const matches = findSecrets(`slack = "${SLACK_TOKEN}"`);
    expect(matches.map((m) => m.patternId)).toContain("slack-token");
    expect(matches.find((m) => m.patternId === "slack-token")).toMatchObject({
      severity: "high",
      confidence: "high",
    });
  });

  it("flags Anthropic keys without also flagging them as OpenAI-style", () => {
    const ids = patternIds(`k = "${ANTHROPIC_KEY}"`);
    expect(ids).toContain("anthropic-key");
    expect(ids).not.toContain("openai-style-key");
  });

  it("flags generic OpenAI-style sk- keys", () => {
    const matches = findSecrets(`k = "${OPENAI_STYLE}"`);
    expect(matches.map((m) => m.patternId)).toContain("openai-style-key");
  });

  it("flags a high-entropy value assigned to a secret-like name", () => {
    const text = `const config = { apiSecret: "${HIGH_ENTROPY_VALUE}" };`;
    const matches = findSecrets(text);
    const generic = matches.find((m) => m.patternId === "generic-assignment");
    expect(generic).toMatchObject({
      severity: "medium",
      confidence: "low",
      value: HIGH_ENTROPY_VALUE,
    });
    expect(generic?.index).toBe(text.indexOf(HIGH_ENTROPY_VALUE));
  });

  it("matches quoted-name JSON style assignments too", () => {
    const text = `{"access_token": "${HIGH_ENTROPY_VALUE}"}`;
    expect(patternIds(text)).toContain("generic-assignment");
  });

  it("does not flag placeholder, low-entropy, or keyword-less values", () => {
    expect(findSecrets(`apiSecret: "your-api-key-here-please"`)).toEqual([]);
    expect(findSecrets(`apiSecret: "${"a".repeat(30)}"`)).toEqual([]);
    expect(findSecrets(`normalVar: "${HIGH_ENTROPY_VALUE}"`)).toEqual([]);
    expect(findSecrets(`apiSecret: "short"`)).toEqual([]);
  });

  it("does not flag publishable keys, AIza keys, or ordinary JWTs", () => {
    const jwt = fakeJwt({ role: "anon" });
    const text = `pk = "pk_test_aaaaaaaaaaaaaaaa"; maps = "AIza${"B".repeat(35)}"; jwt = "${jwt}";`;
    expect(findSecrets(text)).toEqual([]);
  });

  it("de-duplicates by patternId + value, keeping the first index", () => {
    const text = `a="${STRIPE_LIVE}"; b="${STRIPE_LIVE}";`;
    const matches = findSecrets(text);
    const stripe = matches.filter((m) => m.patternId === "stripe-live");
    expect(stripe).toHaveLength(1);
    expect(stripe[0].index).toBe(text.indexOf(STRIPE_LIVE));
  });

  it("finds secrets in minified single-line bundles", () => {
    const text = `!function(){var e={key:"${STRIPE_LIVE}",x:[1,2,3]};console.log(e)}();`;
    expect(patternIds(text)).toContain("stripe-live");
  });
});

describe("findJwts / decodeJwtPayload", () => {
  it("finds JWT-shaped tokens and ignores version strings", () => {
    const jwt = fakeJwt({ role: "service_role" });
    const matches = findJwts(`token="${jwt}" version 1.2.3 end`);
    expect(matches).toHaveLength(1);
    expect(matches[0].value).toBe(jwt);
    expect(findJwts("1.2.3 and not-a-jwt")).toEqual([]);
  });

  it("decodes a valid payload", () => {
    const jwt = fakeJwt({ role: "service_role", iss: "x" });
    expect(decodeJwtPayload(jwt)).toMatchObject({ role: "service_role", iss: "x" });
  });

  it("returns null on malformed input without throwing", () => {
    expect(decodeJwtPayload("not-a-jwt")).toBeNull();
    expect(decodeJwtPayload("a.b")).toBeNull();
    expect(decodeJwtPayload("a.b.c.d")).toBeNull();
    expect(decodeJwtPayload("eyJhbGciOiJ9.!!!notbase64!!!.sig")).toBeNull();
    // Valid base64url but not JSON:
    expect(decodeJwtPayload(`${b64url("h")}.${b64url("5")}.${b64url("s")}`)).toBeNull();
    // JSON array payload is not an object:
    expect(decodeJwtPayload(`${b64url("h")}.${b64url("[1,2]")}.${b64url("s")}`)).toBeNull();
  });
});

describe("regex safety", () => {
  it("scans a ~2 MB pathological string in under 1 second", () => {
    const pathological = [
      "a".repeat(800_000),
      "sk_live_".repeat(60_000),
      "-----BEGIN ".repeat(60_000),
      'apiKey="' + "d".repeat(300_000),
      ('"' + "c".repeat(2_000) + '"').repeat(20),
      "ghp_".repeat(50_000),
      "xoxb-".repeat(50_000),
    ].join("");
    expect(pathological.length).toBeGreaterThan(2 * 1024 * 1024);

    const start = performance.now();
    for (const pattern of SECRET_PATTERNS) {
      pattern.regex.lastIndex = 0;
      for (const _ of pathological.matchAll(pattern.regex)) {
        // exhaust matches
      }
    }
    findSecrets(pathological);
    findJwts(pathological);
    const elapsed = performance.now() - start;
    expect(elapsed).toBeLessThan(1_000);
  });
});
