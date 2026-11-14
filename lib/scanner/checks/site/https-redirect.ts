import type { Check, RawFinding, ScanContext } from "@/lib/scanner/types";

/**
 * site.https.redirect — the submitted site is expected on HTTPS. If the final
 * URL is plain HTTP we flag it outright. Otherwise we probe the HTTP origin
 * once through ctx.fetch: if it does not redirect to HTTPS we flag it. Fetch
 * failures produce no finding because many hosts simply refuse port 80.
 * Needs a longer timeout than the 5s default for the extra request.
 */
export const httpsRedirectCheck: Check = {
  id: "site.https.redirect",
  category: "security",
  target: "site",
  timeoutMs: 12_000,
  async run(ctx: ScanContext): Promise<RawFinding[]> {
    const { finalUrl } = ctx.snapshot;
    const location = finalUrl;

    if (finalUrl.startsWith("http://")) {
      return [
        {
          checkId: this.id,
          severity: "high",
          confidence: "high",
          title: "The site is served over plain HTTP",
          evidence: finalUrl,
          location,
        },
      ];
    }
    if (!finalUrl.startsWith("https://")) {
      return [];
    }

    let httpUrl: string;
    try {
      const url = new URL(finalUrl);
      httpUrl = `http://${url.host}/`;
    } catch {
      return [];
    }

    try {
      const res = await ctx.fetch(httpUrl);
      if (!res.ok) {
        return [];
      }
      if (res.finalUrl.startsWith("https://")) {
        return [];
      }
      return [
        {
          checkId: this.id,
          severity: "high",
          confidence: "medium",
          title: "HTTP does not redirect to HTTPS",
          evidence: res.finalUrl,
          location,
        },
      ];
    } catch {
      return [];
    }
  },
};
