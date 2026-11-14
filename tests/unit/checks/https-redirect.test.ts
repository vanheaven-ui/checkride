import { describe, expect, it } from "vitest";
import { httpsRedirectCheck } from "@/lib/scanner/checks/site/https-redirect";
import type { Fetcher } from "@/lib/scanner/types";
import { okResult } from "../../helpers/fetcher";
import { makeSnapshot } from "../../helpers/snapshot";

function ctxWithFetch(finalUrl: string, fetch: Fetcher) {
  return { snapshot: makeSnapshot({ finalUrl, requestedUrl: finalUrl }), fetch };
}

describe("site.https.redirect", () => {
  it("has a 12s timeout override", () => {
    expect(httpsRedirectCheck.timeoutMs).toBe(12_000);
  });

  it("flags a site whose final URL is plain HTTP without fetching", async () => {
    let called = false;
    const fetch: Fetcher = async (url) => {
      called = true;
      return okResult(url, "");
    };
    const findings = await httpsRedirectCheck.run(ctxWithFetch("http://example.com/", fetch));
    expect(findings).toHaveLength(1);
    expect(findings[0]).toMatchObject({
      severity: "high",
      confidence: "high",
      title: "The site is served over plain HTTP",
    });
    expect(called).toBe(false);
  });

  it("returns nothing when HTTP redirects to HTTPS", async () => {
    const fetch: Fetcher = async (url) => {
      expect(url).toBe("http://example.com/");
      return okResult(url, "", { finalUrl: "https://example.com/" });
    };
    const findings = await httpsRedirectCheck.run(ctxWithFetch("https://example.com/", fetch));
    expect(findings).toEqual([]);
  });

  it("flags HTTP that stays on HTTP", async () => {
    const fetch: Fetcher = async (url) => okResult(url, "", { finalUrl: "http://example.com/" });
    const findings = await httpsRedirectCheck.run(ctxWithFetch("https://example.com/", fetch));
    expect(findings).toHaveLength(1);
    expect(findings[0]).toMatchObject({
      severity: "high",
      confidence: "medium",
      title: "HTTP does not redirect to HTTPS",
    });
  });

  it("returns nothing when the HTTP probe fails or is refused", async () => {
    const failing: Fetcher = async () => ({
      ok: false,
      reason: "network_error",
      message: "connection refused",
    });
    expect(await httpsRedirectCheck.run(ctxWithFetch("https://example.com/", failing))).toEqual([]);

    const throwing: Fetcher = async () => {
      throw new Error("boom");
    };
    expect(await httpsRedirectCheck.run(ctxWithFetch("https://example.com/", throwing))).toEqual(
      [],
    );
  });
});
