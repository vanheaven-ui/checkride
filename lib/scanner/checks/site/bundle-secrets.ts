import { findSecrets } from "@/lib/scanner/patterns/secrets";
import { redactSecret } from "@/lib/scanner/redact";
import type { Check, RawFinding, ScanContext } from "@/lib/scanner/types";

/**
 * Text budget for secret scanning: the HTML plus script bodies, in order.
 * Measured in UTF-16 code units as a proxy for bytes (see DECISIONS.md).
 */
const MAX_SCAN_CHARS = 10 * 1024 * 1024;
const MAX_FINDINGS = 20;

function yieldToEventLoop(): Promise<void> {
  return new Promise((resolve) => setImmediate(resolve));
}

/** origin + pathname only — no query string or fragment. */
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

/**
 * site.bundle.secrets — scans the page HTML and each same-origin script body
 * for leaked credentials. Secrets are never placed in findings: evidence is
 * the pattern name, the redactSecret() form of the value, and its offset.
 */
export const bundleSecretsCheck: Check = {
  id: "site.bundle.secrets",
  category: "secrets",
  target: "site",
  timeoutMs: 15_000,
  async run(ctx: ScanContext): Promise<RawFinding[]> {
    const { snapshot } = ctx;
    const pageLocation = pathOnly(snapshot.finalUrl, snapshot.finalUrl);

    const sources: TextSource[] = [
      { text: snapshot.html, location: pageLocation },
      ...snapshot.scripts.map((script) => ({
        text: script.body,
        location: pathOnly(script.url, script.url),
      })),
    ];

    const findings: RawFinding[] = [];
    const seen = new Set<string>();
    let budget = MAX_SCAN_CHARS;
    let unscannedScripts = 0;
    let budgetExhausted = false;

    for (let i = 0; i < sources.length; i++) {
      const source = sources[i];
      const isScript = i > 0;
      if (isScript) {
        // Yield between script scans so a large bundle cannot starve the loop.
        await yieldToEventLoop();
      }
      if (budget <= 0) {
        budgetExhausted = true;
        if (isScript) {
          unscannedScripts += 1;
        }
        continue;
      }

      const text = source.text.slice(0, budget);
      budget -= text.length;
      const truncatedByBudget = text.length < source.text.length;

      for (const match of findSecrets(text)) {
        const dedupeKey = `${match.patternId}${match.value}${source.location}`;
        if (seen.has(dedupeKey) || findings.length >= MAX_FINDINGS) {
          continue;
        }
        seen.add(dedupeKey);
        findings.push({
          checkId: this.id,
          severity: match.severity,
          confidence: match.confidence,
          title:
            match.confidence === "high"
              ? `${match.name} found in public code`
              : `Possible ${match.name} found in public code`,
          evidence: `${match.name}: ${redactSecret(match.value)} at character ${match.index}`,
          location: source.location,
        });
      }

      if (truncatedByBudget) {
        budgetExhausted = true;
        budget = 0;
      }
    }

    if (budgetExhausted && unscannedScripts > 0) {
      findings.push({
        checkId: this.id,
        severity: "info",
        confidence: "high",
        title: "Not all scripts could be scanned for secrets",
        evidence: `${unscannedScripts} script file(s) were not scanned: the ${MAX_SCAN_CHARS / (1024 * 1024)} MB scan budget was reached first.`,
        location: pageLocation,
      });
    }

    return findings.slice(0, MAX_FINDINGS + (budgetExhausted && unscannedScripts > 0 ? 1 : 0));
  },
};
