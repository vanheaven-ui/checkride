import { describe, expect, it } from "vitest";
import { redactSecret } from "@/lib/scanner/redact";
import { scrubSecrets } from "@/lib/scanner/scrub";

const STRIPE_LIVE = "sk" + "_live_" + "x".repeat(24);

describe("scrubSecrets", () => {
  it("masks a full secret embedded in text", () => {
    const text = `bundle leaked ${STRIPE_LIVE} ok`;
    const scrubbed = scrubSecrets(text);
    expect(scrubbed).not.toContain(STRIPE_LIVE);
    expect(scrubbed).toContain(redactSecret(STRIPE_LIVE));
    expect(scrubbed).toBe(`bundle leaked ${redactSecret(STRIPE_LIVE)} ok`);
  });

  it("returns text without secrets unchanged", () => {
    const text = "Missing Strict-Transport-Security header; see /some/path?q=1";
    expect(scrubSecrets(text)).toBe(text);
  });

  it("masks multiple secrets and keeps surrounding text intact", () => {
    const aws = "AKIA" + "ZZZZYYYYXXXXWWWW";
    const text = `a ${STRIPE_LIVE} b ${aws} c`;
    const scrubbed = scrubSecrets(text);
    expect(scrubbed).not.toContain(STRIPE_LIVE);
    expect(scrubbed).not.toContain(aws);
    expect(scrubbed.startsWith("a ")).toBe(true);
    expect(scrubbed.endsWith(" c")).toBe(true);
  });

  it("handles secrets at the start and end of the text", () => {
    const text = `${STRIPE_LIVE} middle ${STRIPE_LIVE}`;
    const scrubbed = scrubSecrets(text);
    expect(scrubbed).not.toContain(STRIPE_LIVE);
    expect(scrubbed).toContain(" middle ");
  });

  it("masks every occurrence of the same secret", () => {
    const text = Array.from({ length: 5 }, () => STRIPE_LIVE).join(" | ");
    const scrubbed = scrubSecrets(text);
    expect(scrubbed).not.toContain(STRIPE_LIVE);
    expect(scrubbed.split(redactSecret(STRIPE_LIVE))).toHaveLength(6);
  });

  it("masks a secret that is also matched by a broader pattern", () => {
    const text = `apiKey="${STRIPE_LIVE}"`;
    const scrubbed = scrubSecrets(text);
    expect(scrubbed).not.toContain(STRIPE_LIVE);
    expect(scrubbed).not.toContain("xxxxxxxxxxxxxxxx");
  });

  it("is idempotent: scrubbing already-masked text changes nothing", () => {
    const once = scrubSecrets(`leaked ${STRIPE_LIVE} twice ${STRIPE_LIVE}`);
    expect(scrubSecrets(once)).toBe(once);
  });

  it("scrubs a large text quickly", () => {
    const filler = "a".repeat(2_000_000);
    const started = Date.now();
    const scrubbed = scrubSecrets(`${filler} ${STRIPE_LIVE} ${filler}`);
    expect(Date.now() - started).toBeLessThan(2000);
    expect(scrubbed).not.toContain(STRIPE_LIVE);
  });
});
