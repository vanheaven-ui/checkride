import type { Check, RawFinding, ScanContext } from "@/lib/scanner/types";

const FIREBASE_HOST_RE =
  /[\w.-]*(?:firebaseapp\.com|firebaseio\.com|firebasestorage\.app|firebasestorage\.googleapis\.com)/i;
const PROJECT_ID_RE = /["']?projectId["']?\s*:\s*["']([A-Za-z0-9_-]{1,60})["']/i;
const API_KEY_RE = /["']?apiKey["']?\s*:\s*["']AIza[0-9A-Za-z_-]{20,}["']/i;

function pathOnly(url: string, fallback: string): string {
  try {
    const parsed = new URL(url);
    return `${parsed.origin}${parsed.pathname}`;
  } catch {
    return fallback;
  }
}

/**
 * site.backend.firebase — detects a Firebase web config in public code
 * (firebaseapp.com / firebaseio.com / firebasestorage hosts, or a projectId
 * paired with an AIza apiKey). Emits ONE finding asking for manual Security
 * Rules review. The apiKey is never included in evidence. Never contacts
 * Firebase.
 */
export const firebaseCheck: Check = {
  id: "site.backend.firebase",
  category: "security",
  target: "site",
  async run(ctx: ScanContext): Promise<RawFinding[]> {
    const texts = [ctx.snapshot.html, ...ctx.snapshot.scripts.map((s) => s.body)];
    const pageLocation = pathOnly(ctx.snapshot.finalUrl, ctx.snapshot.finalUrl);

    let detected = false;
    let projectId: string | null = null;
    let location = pageLocation;

    for (let i = 0; i < texts.length; i++) {
      const text = texts[i];
      const sourceLocation =
        i === 0
          ? pageLocation
          : pathOnly(ctx.snapshot.scripts[i - 1].url, ctx.snapshot.scripts[i - 1].url);

      const hasHostSignal = FIREBASE_HOST_RE.test(text);
      const projectMatch = PROJECT_ID_RE.exec(text);
      const hasConfigPair = projectMatch !== null && API_KEY_RE.test(text);
      if (!hasHostSignal && !hasConfigPair) {
        continue;
      }

      detected = true;
      location = sourceLocation;
      projectId = projectMatch?.[1] ?? projectId;
      break;
    }

    if (!detected) {
      return [];
    }

    return [
      {
        checkId: this.id,
        severity: "medium",
        confidence: "low",
        title: "Firebase detected: confirm Security Rules restrict access",
        evidence: projectId
          ? `Firebase project "${projectId}" detected in public code. Security Rules cannot be verified from outside Firebase.`
          : "Firebase host reference detected in public code. Security Rules cannot be verified from outside Firebase.",
        location,
      },
    ];
  },
};
