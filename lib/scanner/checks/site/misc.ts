import type { Check, RawFinding, ScanContext } from "@/lib/scanner/types";

function headerValue(ctx: ScanContext, name: string): string | undefined {
  const value = ctx.snapshot.headers[name];
  if (Array.isArray(value)) {
    return value[0];
  }
  return value;
}

/**
 * site.headers.misc — flags a missing or incorrect X-Content-Type-Options
 * (nosniff) and a missing Referrer-Policy. One finding per header.
 */
export const miscCheck: Check = {
  id: "site.headers.misc",
  category: "security",
  target: "site",
  async run(ctx: ScanContext): Promise<RawFinding[]> {
    const findings: RawFinding[] = [];
    const location = ctx.snapshot.finalUrl;

    const nosniff = headerValue(ctx, "x-content-type-options");
    if (nosniff === undefined || nosniff.trim().toLowerCase() !== "nosniff") {
      findings.push({
        checkId: this.id,
        severity: "low",
        confidence: "high",
        title: "Missing or incorrect X-Content-Type-Options header",
        evidence: nosniff !== undefined ? nosniff.slice(0, 300) : "header not present",
        location,
      });
    }

    const referrerPolicy = headerValue(ctx, "referrer-policy");
    if (referrerPolicy === undefined || referrerPolicy.trim() === "") {
      findings.push({
        checkId: this.id,
        severity: "low",
        confidence: "high",
        title: "Missing Referrer-Policy header",
        evidence: "header not present",
        location,
      });
    }

    return findings;
  },
};
