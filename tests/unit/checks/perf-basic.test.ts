import { describe, expect, it } from "vitest";
import { perfBasicCheck } from "@/lib/scanner/checks/site/perf-basic";
import { makeContext } from "../../helpers/snapshot";

function script(url: string, body: string, truncated = false) {
  return { url, body, truncated };
}

function imgs(count: number, attrs = ""): string {
  return Array.from({ length: count }, (_, i) => `<img src="/i${i}.png"${attrs} />`).join("");
}

describe("site.perf.basic", () => {
  it("returns nothing for a fast, small page", async () => {
    const findings = await perfBasicCheck.run(makeContext());
    expect(findings).toEqual([]);
  });

  it("flags response time above 1500ms as low and above 3000ms as medium", async () => {
    const low = await perfBasicCheck.run(makeContext({ fetchMs: 1600 }));
    expect(low).toHaveLength(1);
    expect(low[0]).toMatchObject({ severity: "low", confidence: "medium" });

    const med = await perfBasicCheck.run(makeContext({ fetchMs: 3100 }));
    expect(med[0]).toMatchObject({ severity: "medium", confidence: "medium" });

    const ok = await perfBasicCheck.run(makeContext({ fetchMs: 1500 }));
    expect(ok).toEqual([]);
  });

  it("flags HTML over 500 KB", async () => {
    const findings = await perfBasicCheck.run(
      makeContext({ html: `<html>${"a".repeat(501 * 1024)}</html>` }),
    );
    const f = findings.find((x) => x.title === "Large HTML document");
    expect(f).toMatchObject({ severity: "low", confidence: "medium" });
  });

  it("flags total script bytes with uncompressed-size evidence", async () => {
    const body = "x".repeat(3 * 1024 * 1024);
    const findings = await perfBasicCheck.run(
      makeContext({ scripts: [script("https://example.com/big.js", body)] }),
    );
    const f = findings.find((x) => x.title === "Large total script size");
    expect(f).toMatchObject({ severity: "low", confidence: "medium" });
    expect(f?.evidence).toContain("uncompressed");
    expect(f?.evidence).toContain("3145728");
  });

  it("flags script sizes above 5 MB as medium", async () => {
    const body = "x".repeat(6 * 1024 * 1024);
    const findings = await perfBasicCheck.run(
      makeContext({ scripts: [script("https://example.com/huge.js", body)] }),
    );
    const f = findings.find((x) => x.title === "Very large total script size");
    expect(f).toMatchObject({ severity: "medium" });
  });

  it("emits a note instead of the size finding when a script was truncated", async () => {
    const body = "x".repeat(3 * 1024 * 1024);
    const findings = await perfBasicCheck.run(
      makeContext({ scripts: [script("https://example.com/big.js", body, true)] }),
    );
    expect(findings.find((x) => x.title === "Large total script size")).toBeUndefined();
    const note = findings.find((x) => x.title === "Script sizes may be incomplete");
    expect(note).toMatchObject({ severity: "info" });
  });

  it("emits a note instead when snapshot notes record skipped scripts", async () => {
    const body = "x".repeat(3 * 1024 * 1024);
    const findings = await perfBasicCheck.run(
      makeContext({
        scripts: [script("https://example.com/big.js", body)],
        notes: ["Skipped 2 script file(s) (limit of 15)."],
      }),
    );
    expect(findings.find((x) => x.title === "Large total script size")).toBeUndefined();
    expect(findings.find((x) => x.title === "Script sizes may be incomplete")).toBeDefined();
  });

  it("flags 5+ img tags with neither width nor height", async () => {
    const findings = await perfBasicCheck.run(
      makeContext({ html: `<html><body>${imgs(5)}</body></html>` }),
    );
    const f = findings.find((x) => x.title === "Images missing width and height attributes");
    expect(f).toMatchObject({ severity: "low", confidence: "medium" });
    expect(f?.evidence).toContain("5");
  });

  it("does not count imgs that have width or height, and stays quiet under 5", async () => {
    const html = `<html><body>${imgs(3)}${imgs(3, ' width="10"')}${imgs(2, ' height="10"')}</body></html>`;
    const findings = await perfBasicCheck.run(makeContext({ html }));
    expect(
      findings.find((x) => x.title === "Images missing width and height attributes"),
    ).toBeUndefined();
  });
});
