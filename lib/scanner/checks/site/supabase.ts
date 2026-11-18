import { decodeJwtPayload, findJwts } from "@/lib/scanner/patterns/secrets";
import { redactSecret } from "@/lib/scanner/redact";
import type { Check, RawFinding, ScanContext } from "@/lib/scanner/types";

const PROJECT_URL_RE = /https:\/\/[a-z0-9]{20}\.supabase\.co/g;
/** Cap JWT decoding work; bundles can contain many tokens. */
const MAX_JWTS_EXAMINED = 200;

function pathOnly(url: string, fallback: string): string {
  try {
    const parsed = new URL(url);
    return `${parsed.origin}${parsed.pathname}`;
  } catch {
    return fallback;
  }
}

type TextSource = {
  text: string;
  location: string;
};

function sources(ctx: ScanContext): TextSource[] {
  const pageLocation = pathOnly(ctx.snapshot.finalUrl, ctx.snapshot.finalUrl);
  return [
    { text: ctx.snapshot.html, location: pageLocation },
    ...ctx.snapshot.scripts.map((script) => ({
      text: script.body,
      location: pathOnly(script.url, script.url),
    })),
  ];
}

/**
 * site.backend.supabase — detects Supabase project URLs and JWTs in public
 * code. A service_role JWT is critical; a project URL plus an anon-role JWT
 * is informational because anon keys are expected to be public — the finding
 * asks for manual Row Level Security review. Never contacts Supabase.
 */
export const supabaseCheck: Check = {
  id: "site.backend.supabase",
  category: "security",
  target: "site",
  async run(ctx: ScanContext): Promise<RawFinding[]> {
    const projectUrls = new Set<string>();
    const serviceRoleTokens: { value: string; location: string }[] = [];
    const seenTokens = new Set<string>();
    let anonToken: { value: string; location: string } | null = null;
    let jwtsExamined = 0;

    for (const source of sources(ctx)) {
      PROJECT_URL_RE.lastIndex = 0;
      for (const match of source.text.matchAll(PROJECT_URL_RE)) {
        projectUrls.add(match[0]);
      }

      if (jwtsExamined >= MAX_JWTS_EXAMINED) {
        continue;
      }
      for (const jwt of findJwts(source.text)) {
        if (jwtsExamined >= MAX_JWTS_EXAMINED) {
          break;
        }
        jwtsExamined += 1;
        if (seenTokens.has(jwt.value)) {
          continue;
        }
        seenTokens.add(jwt.value);
        const payload = decodeJwtPayload(jwt.value);
        const role = payload?.role;
        if (role === "service_role") {
          serviceRoleTokens.push({ value: jwt.value, location: source.location });
        } else if (role === "anon" && anonToken === null) {
          anonToken = { value: jwt.value, location: source.location };
        }
      }
    }

    const findings: RawFinding[] = [];

    if (serviceRoleTokens.length > 0) {
      const first = serviceRoleTokens[0];
      const extra =
        serviceRoleTokens.length > 1 ? ` (${serviceRoleTokens.length} tokens found)` : "";
      findings.push({
        checkId: this.id,
        severity: "critical",
        confidence: "high",
        title: "A Supabase service role key appears in public code",
        evidence: `service_role JWT ${redactSecret(first.value)} at ${first.location}${extra}`,
        location: first.location,
      });
    }

    if (projectUrls.size > 0 && anonToken !== null) {
      const projectUrl = [...projectUrls][0];
      findings.push({
        checkId: this.id,
        severity: "info",
        confidence: "high",
        title: "Supabase detected: confirm Row Level Security is enabled on every table",
        evidence: `Project ${projectUrl} with an anon-role JWT ${redactSecret(anonToken.value)}. Row Level Security cannot be verified from outside the database.`,
        location: anonToken.location,
      });
    }

    return findings;
  },
};
