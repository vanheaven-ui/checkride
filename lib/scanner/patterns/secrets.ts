import type { Confidence, Severity } from "@/lib/scanner/types";

/**
 * Shared secret-detection patterns. Used by site.bundle.secrets now and by the
 * repo checks in Phase 3. Every regex must stay linear: bounded quantifiers
 * only, no nested quantifiers, no unbounded ambiguity — a 2 MB pathological
 * input must scan in well under a second (see tests/unit/patterns/secrets.test.ts).
 */

export type SecretPattern = {
  id: string;
  name: string;
  /** Global regex; capture groups select the reported value and name. */
  regex: RegExp;
  /** Index of the capture group holding the secret value (default: whole match). */
  valueGroup?: number;
  /** Index of the capture group holding the assignment name, if any. */
  nameGroup?: number;
  severity: Severity;
  confidence: Confidence;
  /** Extra per-match validation (entropy, placeholder filters). */
  accept?: (value: string, name: string | undefined) => boolean;
};

export type SecretMatch = {
  patternId: string;
  name: string;
  severity: Severity;
  confidence: Confidence;
  value: string;
  index: number;
};

const MIN_GENERIC_VALUE_LENGTH = 24;
const MAX_GENERIC_VALUE_LENGTH = 256;
const MAX_GENERIC_NAME_LENGTH = 128;
const GENERIC_NAME_KEYWORD = /(?:secret|api[-_]?key|access[-_]?token|private[-_]?key)/i;
const PLACEHOLDER_VALUE = /xxxx|your|example|changeme|test/i;
const MIN_GENERIC_ENTROPY = 3.5;

function shannonEntropy(value: string): number {
  const counts = new Map<string, number>();
  for (const char of value) {
    counts.set(char, (counts.get(char) ?? 0) + 1);
  }
  let entropy = 0;
  for (const count of counts.values()) {
    const p = count / value.length;
    entropy -= p * Math.log2(p);
  }
  return entropy;
}

function acceptGenericAssignment(value: string, name: string | undefined): boolean {
  if (name === undefined || !GENERIC_NAME_KEYWORD.test(name)) {
    return false;
  }
  if (PLACEHOLDER_VALUE.test(value)) {
    return false;
  }
  return shannonEntropy(value) >= MIN_GENERIC_ENTROPY;
}

export const SECRET_PATTERNS: readonly SecretPattern[] = [
  {
    id: "stripe-live",
    name: "Stripe live secret key",
    regex: /\b(?:sk|rk)_live_[A-Za-z0-9]{16,}/g,
    severity: "critical",
    confidence: "high",
  },
  {
    id: "stripe-test",
    name: "Stripe test secret key",
    regex: /\b(?:sk|rk)_test_[A-Za-z0-9]{16,}/g,
    severity: "medium",
    confidence: "high",
  },
  {
    id: "aws-access-key",
    name: "AWS access key ID",
    // AKIAIOSFODNN7EXAMPLE is AWS's documented example and is filtered out.
    regex: /\bAKIA[0-9A-Z]{16}\b/g,
    severity: "critical",
    confidence: "medium",
    accept: (value) => value !== "AKIAIOSFODNN7EXAMPLE",
  },
  {
    id: "private-key-block",
    name: "Private key block",
    regex: /-----BEGIN [A-Z0-9 ]{0,32}PRIVATE KEY-----/g,
    severity: "critical",
    confidence: "high",
  },
  {
    id: "github-token",
    name: "GitHub token",
    regex: /\b(?:gh[pousr]_[A-Za-z0-9]{20,}|github_pat_[A-Za-z0-9_]{20,})\b/g,
    severity: "critical",
    confidence: "high",
  },
  {
    id: "slack-token",
    name: "Slack token",
    regex: /\bxox[baprs]-[A-Za-z0-9-]{10,}/g,
    severity: "high",
    confidence: "high",
  },
  {
    id: "anthropic-key",
    name: "Anthropic API key",
    regex: /\bsk-ant-[A-Za-z0-9_-]{20,}/g,
    severity: "critical",
    confidence: "high",
  },
  {
    id: "openai-style-key",
    name: "OpenAI-style API key",
    regex: /\bsk-(?!ant-)[A-Za-z0-9_-]{20,}/g,
    severity: "critical",
    confidence: "medium",
  },
  {
    id: "generic-assignment",
    name: "High-entropy assigned value",
    // name := "value" or "name": "value". The lookbehind keeps the scan
    // linear: positions inside a run of name characters fail immediately.
    regex: new RegExp(
      String.raw`(?<![A-Za-z0-9_.\-])["']?([A-Za-z0-9_.\-]{0,${MAX_GENERIC_NAME_LENGTH}})["']?\s*[:=]\s*(["'])([A-Za-z0-9_\-+/=]{${MIN_GENERIC_VALUE_LENGTH},${MAX_GENERIC_VALUE_LENGTH}})\2`,
      "gd",
    ),
    severity: "medium",
    confidence: "low",
    valueGroup: 3,
    nameGroup: 1,
    accept: (value, name) => acceptGenericAssignment(value, name),
  },
];

/**
 * Find all secret matches in `text`, de-duplicated by patternId + value
 * (first occurrence wins). Never throws.
 */
export function findSecrets(text: string): SecretMatch[] {
  const seen = new Set<string>();
  const matches: SecretMatch[] = [];

  for (const pattern of SECRET_PATTERNS) {
    // Reset lastIndex: patterns are module-level globals reused across calls.
    pattern.regex.lastIndex = 0;
    for (const match of text.matchAll(pattern.regex)) {
      const valueGroup = pattern.valueGroup ?? 0;
      const value = match[valueGroup] ?? match[0];
      const name = pattern.nameGroup === undefined ? undefined : match[pattern.nameGroup];
      // Report the offset of the secret value itself.
      const index = match.indices?.[valueGroup]?.[0] ?? match.index ?? 0;
      if (pattern.accept && !pattern.accept(value, name)) {
        continue;
      }
      const dedupeKey = `${pattern.id}${value}`;
      if (seen.has(dedupeKey)) {
        continue;
      }
      seen.add(dedupeKey);
      matches.push({
        patternId: pattern.id,
        name: pattern.name,
        severity: pattern.severity,
        confidence: pattern.confidence,
        value,
        index,
      });
    }
  }

  return matches.sort((a, b) => a.index - b.index);
}

const JWT_RE = /\beyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\b/g;

export type JwtMatch = {
  value: string;
  index: number;
};

/** Find JWT-shaped tokens (header.payload.signature, header starts "eyJ"). */
export function findJwts(text: string): JwtMatch[] {
  JWT_RE.lastIndex = 0;
  const matches: JwtMatch[] = [];
  for (const match of text.matchAll(JWT_RE)) {
    matches.push({ value: match[0], index: match.index ?? 0 });
  }
  return matches;
}

/**
 * Decode a JWT payload without verifying the signature. Returns the payload
 * object, or null on ANY problem (wrong shape, bad base64url, bad JSON,
 * non-object payload). Never throws.
 */
export function decodeJwtPayload(token: string): Record<string, unknown> | null {
  try {
    const parts = token.split(".");
    if (parts.length !== 3 || parts[1] === "") {
      return null;
    }
    const json = Buffer.from(parts[1], "base64url").toString("utf8");
    const parsed: unknown = JSON.parse(json);
    if (typeof parsed === "object" && parsed !== null && !Array.isArray(parsed)) {
      return parsed as Record<string, unknown>;
    }
    return null;
  } catch {
    return null;
  }
}
