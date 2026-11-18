import { findSecrets } from "@/lib/scanner/patterns/secrets";
import { redactSecret } from "@/lib/scanner/redact";

/**
 * Defensive scrub applied to every finding field before persistence: run the
 * secret patterns over the text and mask EVERY occurrence of every secret found.
 *
 * findSecrets de-duplicates by pattern and value (right for reporting, wrong for
 * scrubbing), so we collect the distinct values and replace all occurrences of
 * each. Longest values go first so a secret nested inside a longer match is
 * covered by the longer replacement.
 */
export function scrubSecrets(text: string): string {
  const values = [...new Set(findSecrets(text).map((match) => match.value))]
    .filter((value) => value.length > 0)
    .sort((a, b) => b.length - a.length);

  if (values.length === 0) {
    return text;
  }

  let scrubbed = text;
  for (const value of values) {
    scrubbed = scrubbed.split(value).join(redactSecret(value));
  }
  return scrubbed;
}
