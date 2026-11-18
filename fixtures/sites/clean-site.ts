import type { FixtureRoute } from "../../tests/helpers/fixture-server";

// Benign public values, assembled at runtime so no key-shaped literal exists
// in the repo. The Maps key is deliberately low-entropy so the generic
// high-entropy secret pattern stays quiet, matching a real browser key.
const GMAPS_BROWSER_KEY = "AIza" + "Qq7".repeat(12);
const STRIPE_PUBLISHABLE_KEY = "pk" + "_test_" + "y".repeat(24);

const HOME_HTML = `<!doctype html>
<html lang="en">
  <head>
    <title>Clean Fixture</title>
    <script src="/static/main.js"></script>
  </head>
  <body>
    <h1>Clean Fixture</h1>
    <p>A fixture site that passes the Phase 2 checks.</p>
    <img src="/img/a.png" alt="a" />
    <img src="/img/b.png" alt="b" width="100" />
    <img src="/img/c.png" alt="c" height="80" />
  </body>
</html>`;

const MAIN_JS = `// clean bundle: publishable keys and a maps browser key are public by design
const stripePublishableKey = "${STRIPE_PUBLISHABLE_KEY}";
const googleMapsConfig = { browserKey: "${GMAPS_BROWSER_KEY}", region: "us" };
export function init() {
  return [stripePublishableKey.length, googleMapsConfig.region];
}`;

/**
 * A fixture site that passes the checks: strong security headers, a clean
 * cookie, a tiny script bundle, and only publishable/browser keys — which are
 * public by design and must NOT be flagged as secrets.
 */
export const cleanSite: Record<string, FixtureRoute> = {
  "/": {
    headers: {
      "strict-transport-security": "max-age=31536000; includeSubDomains",
      "content-security-policy": "default-src 'self'; script-src 'self'",
      "x-frame-options": "DENY",
      "x-content-type-options": "nosniff",
      "referrer-policy": "strict-origin-when-cross-origin",
      "set-cookie": "session=fixturevalue; Path=/; HttpOnly; SameSite=Lax",
    },
    body: HOME_HTML,
  },
  "/static/main.js": { headers: { "content-type": "text/javascript" }, body: MAIN_JS },
  "/robots.txt": {
    headers: { "content-type": "text/plain" },
    body: "User-agent: *\nAllow: /\n",
  },
};
