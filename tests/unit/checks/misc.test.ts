import { describe, expect, it } from "vitest";
import { miscCheck } from "@/lib/scanner/checks/site/misc";
import { makeContext } from "../../helpers/snapshot";

describe("site.headers.misc", () => {
  it("emits one finding per missing header", async () => {
    const findings = await miscCheck.run(makeContext());
    expect(findings).toHaveLength(2);
    expect(findings.map((f) => f.title)).toEqual([
      "Missing or incorrect X-Content-Type-Options header",
      "Missing Referrer-Policy header",
    ]);
    for (const f of findings) {
      expect(f).toMatchObject({ severity: "low", confidence: "high" });
    }
  });

  it("flags a non-nosniff X-Content-Type-Options value", async () => {
    const findings = await miscCheck.run(
      makeContext({
        headers: {
          "x-content-type-options": "something-else",
          "referrer-policy": "no-referrer",
        },
      }),
    );
    expect(findings).toHaveLength(1);
    expect(findings[0]?.title).toContain("X-Content-Type-Options");
    expect(findings[0]?.evidence).toBe("something-else");
  });

  it("accepts nosniff case-insensitively and any referrer-policy", async () => {
    const findings = await miscCheck.run(
      makeContext({
        headers: {
          "x-content-type-options": "NoSniff",
          "referrer-policy": "strict-origin",
        },
      }),
    );
    expect(findings).toEqual([]);
  });
});
