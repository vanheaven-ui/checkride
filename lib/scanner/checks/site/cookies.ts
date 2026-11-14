import type { Check, RawFinding, ScanContext } from "@/lib/scanner/types";

const MAX_NAMES = 5;
const SENSITIVE_NAME = /sess|auth|token|jwt|sid/i;

type ParsedCookie = {
  name: string;
  secure: boolean;
  httpOnly: boolean;
  sameSite: string | null;
};

function parseCookie(raw: string): ParsedCookie | null {
  const segments = raw.split(";");
  const pair = segments[0];
  const eq = pair.indexOf("=");
  const name = (eq === -1 ? pair : pair.slice(0, eq)).trim();
  if (name === "") {
    return null;
  }

  let secure = false;
  let httpOnly = false;
  let sameSite: string | null = null;

  for (const segment of segments.slice(1)) {
    const attr = segment.trim();
    if (attr === "") {
      continue;
    }
    const eqIndex = attr.indexOf("=");
    const key = (eqIndex === -1 ? attr : attr.slice(0, eqIndex)).trim().toLowerCase();
    const value = eqIndex === -1 ? "" : attr.slice(eqIndex + 1).trim();

    if (key === "secure") {
      secure = true;
    } else if (key === "httponly") {
      httpOnly = true;
    } else if (key === "samesite") {
      sameSite = value.toLowerCase() || null;
    }
  }

  return { name, secure, httpOnly, sameSite };
}

function namesEvidence(names: string[]): string {
  const shown = names.slice(0, MAX_NAMES).join(", ");
  const extra = names.length - MAX_NAMES;
  return `Cookie names: ${shown}${extra > 0 ? ` (+${extra} more)` : ""}`;
}

/**
 * site.cookies — groups cookies by issue type and emits ONE finding per type,
 * listing at most 5 cookie NAMES. Cookie values are never included anywhere.
 */
export const cookiesCheck: Check = {
  id: "site.cookies",
  category: "security",
  target: "site",
  async run(ctx: ScanContext): Promise<RawFinding[]> {
    const raw = ctx.snapshot.headers["set-cookie"];
    if (!Array.isArray(raw) || raw.length === 0) {
      return [];
    }

    const cookies = raw.map(parseCookie).filter((c): c is ParsedCookie => c !== null);
    if (cookies.length === 0) {
      return [];
    }

    const isHttps = ctx.snapshot.finalUrl.startsWith("https://");
    const findings: RawFinding[] = [];
    const location = ctx.snapshot.finalUrl;

    const push = (
      severity: RawFinding["severity"],
      confidence: RawFinding["confidence"],
      title: string,
      names: string[],
    ) => {
      findings.push({
        checkId: this.id,
        severity,
        confidence,
        title,
        evidence: namesEvidence(names),
        location,
      });
    };

    if (isHttps) {
      const missingSecure = cookies.filter((c) => !c.secure).map((c) => c.name);
      if (missingSecure.length > 0) {
        push("medium", "high", "Cookies missing the Secure flag on an HTTPS page", missingSecure);
      }
    }

    const noneWithoutSecure = cookies
      .filter((c) => c.sameSite === "none" && !c.secure)
      .map((c) => c.name);
    if (noneWithoutSecure.length > 0) {
      push(
        "medium",
        "high",
        "Cookies with SameSite=None but without the Secure flag",
        noneWithoutSecure,
      );
    }

    const missingHttpOnly = cookies.filter((c) => !c.httpOnly);
    const sensitive = missingHttpOnly.filter((c) => SENSITIVE_NAME.test(c.name)).map((c) => c.name);
    const other = missingHttpOnly.filter((c) => !SENSITIVE_NAME.test(c.name)).map((c) => c.name);
    if (sensitive.length > 0) {
      push("medium", "medium", "Session-like cookies missing the HttpOnly flag", sensitive);
    }
    if (other.length > 0) {
      push("low", "medium", "Cookies missing the HttpOnly flag", other);
    }

    const missingSameSite = cookies.filter((c) => c.sameSite === null).map((c) => c.name);
    if (missingSameSite.length > 0) {
      push("low", "medium", "Cookies missing the SameSite attribute", missingSameSite);
    }

    return findings;
  },
};
