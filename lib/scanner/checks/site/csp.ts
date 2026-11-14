import type { Check, RawFinding, ScanContext } from "@/lib/scanner/types";

const ENFORCING_CSP = "content-security-policy";
const REPORT_ONLY_CSP = "content-security-policy-report-only";
const MAX_EVIDENCE = 300;

function headerValue(ctx: ScanContext, name: string): string | undefined {
  const value = ctx.snapshot.headers[name];
  if (Array.isArray(value)) {
    return value[0];
  }
  return value;
}

type CspDirective = { name: string; value: string; tokens: string[] };

function parseCsp(header: string): CspDirective[] {
  return header
    .split(";")
    .map((part) => part.trim())
    .filter((part) => part !== "")
    .map((part) => {
      const [name, ...rest] = part.split(/\s+/);
      return {
        name: name.toLowerCase(),
        value: part,
        tokens: rest.map((t) => t.toLowerCase()),
      };
    });
}

// const NONCE_OR_HASH = /^(nonce-|sha256-|sha384-|sha512-)/;
const NONCE_OR_HASH = /^'(nonce-|sha(256|384|512)-)/;

/**
 * site.headers.csp — flags a missing CSP, a report-only CSP, or an enforcing
 * script-src/default-src that allows unsafe script execution. When a nonce,
 * hash source, or 'strict-dynamic' is present browsers ignore 'unsafe-inline',
 * so that token alone does not trigger the finding; 'unsafe-eval' always does.
 */
export const cspCheck: Check = {
  id: "site.headers.csp",
  category: "security",
  target: "site",
  async run(ctx: ScanContext): Promise<RawFinding[]> {
    const location = ctx.snapshot.finalUrl;
    const enforcing = headerValue(ctx, ENFORCING_CSP);
    const reportOnly = headerValue(ctx, REPORT_ONLY_CSP);

    if (enforcing === undefined) {
      if (reportOnly !== undefined) {
        return [
          {
            checkId: this.id,
            severity: "low",
            confidence: "high",
            title: "CSP is report-only",
            evidence: reportOnly.slice(0, MAX_EVIDENCE),
            location,
          },
        ];
      }
      return [
        {
          checkId: this.id,
          severity: "medium",
          confidence: "high",
          title: "No Content-Security-Policy header",
          evidence: "header not present",
          location,
        },
      ];
    }

    const directives = parseCsp(enforcing);
    const scriptDirective =
      directives.find((d) => d.name === "script-src") ??
      directives.find((d) => d.name === "default-src");
    if (!scriptDirective) {
      return [];
    }

    const hasNonceOrHash = scriptDirective.tokens.some((t) => NONCE_OR_HASH.test(t));
    const hasStrictDynamic = scriptDirective.tokens.includes("'strict-dynamic'");
    const unsafeInlineIgnored = hasNonceOrHash || hasStrictDynamic;
    const unsafeInline = scriptDirective.tokens.includes("'unsafe-inline'") && !unsafeInlineIgnored;
    const unsafeEval = scriptDirective.tokens.includes("'unsafe-eval'");

    if (unsafeInline || unsafeEval) {
      return [
        {
          checkId: this.id,
          severity: "low",
          confidence: "medium",
          title: "CSP allows unsafe script execution",
          evidence: scriptDirective.value.slice(0, MAX_EVIDENCE),
          location,
        },
      ];
    }

    return [];
  },
};
