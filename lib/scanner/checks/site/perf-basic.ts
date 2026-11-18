import type { Check, RawFinding, ScanContext } from "@/lib/scanner/types";

const RESPONSE_TIME_LOW_MS = 1_500;
const RESPONSE_TIME_MEDIUM_MS = 3_000;
const HTML_SIZE_LOW_BYTES = 500 * 1024;
const SCRIPT_SIZE_LOW_BYTES = 2 * 1024 * 1024;
const SCRIPT_SIZE_MEDIUM_BYTES = 5 * 1024 * 1024;
const MIN_IMAGES_WITHOUT_DIMENSIONS = 5;

const IMG_TAG_RE = /<img\b[^>]*>/gi;
const WIDTH_ATTR_RE = /\bwidth\s*=/i;
const HEIGHT_ATTR_RE = /\bheight\s*=/i;

function pathOnly(url: string, fallback: string): string {
  try {
    const parsed = new URL(url);
    return `${parsed.origin}${parsed.pathname}`;
  } catch {
    return fallback;
  }
}

function countImagesWithoutDimensions(html: string): number {
  IMG_TAG_RE.lastIndex = 0;
  let count = 0;
  for (const match of html.matchAll(IMG_TAG_RE)) {
    if (!WIDTH_ATTR_RE.test(match[0]) && !HEIGHT_ATTR_RE.test(match[0])) {
      count += 1;
    }
  }
  return count;
}

/**
 * site.perf.basic — coarse performance signals from the snapshot: response
 * time, HTML size, total uncompressed script bytes, and <img> tags missing
 * both width and height. All findings are confidence "medium" and capped at
 * severity "medium" by construction.
 */
export const perfBasicCheck: Check = {
  id: "site.perf.basic",
  category: "performance",
  target: "site",
  async run(ctx: ScanContext): Promise<RawFinding[]> {
    const { snapshot } = ctx;
    const location = pathOnly(snapshot.finalUrl, snapshot.finalUrl);
    const findings: RawFinding[] = [];

    const push = (severity: RawFinding["severity"], title: string, evidence: string) => {
      findings.push({
        checkId: this.id,
        severity,
        confidence: "medium",
        title,
        evidence,
        location,
      });
    };

    if (snapshot.fetchMs > RESPONSE_TIME_MEDIUM_MS) {
      push(
        "medium",
        "Slow server response time",
        `Home page took ${Math.round(snapshot.fetchMs)} ms to respond.`,
      );
    } else if (snapshot.fetchMs > RESPONSE_TIME_LOW_MS) {
      push(
        "low",
        "Slow server response time",
        `Home page took ${Math.round(snapshot.fetchMs)} ms to respond.`,
      );
    }

    const htmlBytes = Buffer.byteLength(snapshot.html, "utf8");
    if (htmlBytes > HTML_SIZE_LOW_BYTES) {
      push("low", "Large HTML document", `HTML is ${htmlBytes} bytes.`);
    }

    const scriptBytes = snapshot.scripts.reduce(
      (total, script) => total + Buffer.byteLength(script.body, "utf8"),
      0,
    );
    const anyScriptTruncated = snapshot.scripts.some((script) => script.truncated);
    const anyScriptSkipped = snapshot.notes.some((note) => /script/i.test(note));

    if (snapshot.scripts.length > 0 && (anyScriptTruncated || anyScriptSkipped)) {
      push(
        "info",
        "Script sizes may be incomplete",
        "Some scripts were truncated or skipped during the scan, so total script size is a lower bound.",
      );
    } else if (scriptBytes > SCRIPT_SIZE_MEDIUM_BYTES) {
      push(
        "medium",
        "Very large total script size",
        `Total uncompressed script size is ${scriptBytes} bytes across ${snapshot.scripts.length} file(s).`,
      );
    } else if (scriptBytes > SCRIPT_SIZE_LOW_BYTES) {
      push(
        "low",
        "Large total script size",
        `Total uncompressed script size is ${scriptBytes} bytes across ${snapshot.scripts.length} file(s).`,
      );
    }

    const imagesWithoutDimensions = countImagesWithoutDimensions(snapshot.html);
    if (imagesWithoutDimensions >= MIN_IMAGES_WITHOUT_DIMENSIONS) {
      push(
        "low",
        "Images missing width and height attributes",
        `${imagesWithoutDimensions} <img> tags have neither a width nor a height attribute.`,
      );
    }

    return findings;
  },
};
