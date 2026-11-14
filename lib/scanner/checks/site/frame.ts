import type { Check, RawFinding, ScanContext } from "@/lib/scanner/types";

const MAX_EVIDENCE = 300;

function headerValue(ctx: ScanContext, name: string): string | undefined {
  const value = ctx.snapshot.headers[name];
  if (Array.isArray(value)) {
    return value[0];
  }
  return value;
}

function cspHasFrameAncestors(ctx: ScanContext): boolean {
  const csp = headerValue(ctx, "content-security-policy");
  if (csp === undefined) {
    return false;
  }
  return csp
    .split(";")
    .some((directive) => directive.trim().toLowerCase().startsWith("frame-ancestors"));
}

/**
 * site.headers.frame — flags pages that can be embedded in other sites
 * (clickjacking). Protected by X-Frame-Options DENY/SAMEORIGIN or a CSP
 * frame-ancestors directive.
 */
export const frameCheck: Check = {
  id: "site.headers.frame",
  category: "security",
  target: "site",
  async run(ctx: ScanContext): Promise<RawFinding[]> {
    const xfo = headerValue(ctx, "x-frame-options");
    const normalized = xfo?.trim().toUpperCase();
    if (normalized === "DENY" || normalized === "SAMEORIGIN") {
      return [];
    }
    if (cspHasFrameAncestors(ctx)) {
      return [];
    }

    return [
      {
        checkId: this.id,
        severity: "low",
        confidence: "high",
        title: "Page can be embedded in other sites (clickjacking risk)",
        evidence: xfo !== undefined ? xfo.slice(0, MAX_EVIDENCE) : "header not present",
        location: ctx.snapshot.finalUrl,
      },
    ];
  },
};
