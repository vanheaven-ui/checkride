import type { FixtureRoute } from "../../tests/helpers/fixture-server";

const b64url = (value: string) => Buffer.from(value, "utf8").toString("base64url");

function fakeJwt(payload: Record<string, unknown>): string {
  const header = b64url(JSON.stringify({ alg: "HS256", typ: "JWT" }));
  const body = b64url(JSON.stringify(payload));
  const signature = b64url("not-a-real-signature");
  return `${header}.${body}.${signature}`;
}

// Fake secrets are built at runtime so no secret-shaped literal exists in the
// repo; the fixture server still serves the fully-assembled strings.
export const VULN_STRIPE_KEY = "sk" + "_live_" + "x".repeat(24);
export const VULN_SUPABASE_PROJECT = "abcdefghijklmnopqrst";
export const VULN_SUPABASE_URL = `https://${VULN_SUPABASE_PROJECT}.supabase.co`;
export const VULN_SERVICE_JWT = fakeJwt({
  role: "service_role",
  iss: `${VULN_SUPABASE_URL}/auth/v1`,
  exp: 4_000_000_000,
});
export const VULN_ANON_JWT = fakeJwt({
  role: "anon",
  iss: `${VULN_SUPABASE_URL}/auth/v1`,
  exp: 4_000_000_000,
});
const VULN_FIREBASE_PROJECT = "demo-launchcheck";
// Low-entropy on purpose: realistic entropy would trip the generic
// high-entropy-assignment secret pattern, which is not what this fixture
// is meant to exercise.
const VULN_FIREBASE_API_KEY = "AIza" + "Zz9".repeat(12);

const HOME_HTML = `<!doctype html>
<html lang="en">
  <head>
    <title>Fixture App</title>
    <script src="/static/app.js"></script>
    <link rel="modulepreload" href="/static/vendor.js" />
  </head>
  <body>
    <h1>Fixture App</h1>
    <p>A small fixture site for scanner tests.</p>
  </body>
</html>`;

const APP_JS = `// minified-ish bundle exposing credentials in public code
const stripeKey = "${VULN_STRIPE_KEY}";
const supabaseUrl = "${VULN_SUPABASE_URL}";
const serviceJwt = "${VULN_SERVICE_JWT}";
const anonJwt = "${VULN_ANON_JWT}";
const firebaseConfig = {
  apiKey: "${VULN_FIREBASE_API_KEY}",
  authDomain: "${VULN_FIREBASE_PROJECT}.firebaseapp.com",
  projectId: "${VULN_FIREBASE_PROJECT}",
  databaseURL: "https://${VULN_FIREBASE_PROJECT}.firebaseio.com",
  storageBucket: "${VULN_FIREBASE_PROJECT}.firebasestorage.app"
};
console.log("fixture app bundle", stripeKey.length, supabaseUrl, serviceJwt.length, anonJwt.length, firebaseConfig.projectId);`;

const VENDOR_JS = `export const vendor = true;`;

/**
 * A fixture site with several issues: no HSTS/CSP/frame/nosniff/referrer
 * headers (and served over plain HTTP), a flagless session cookie, and a
 * script bundle that leaks a Stripe live key, Supabase credentials, and a
 * Firebase config. All fake values are assembled at runtime.
 */
export const vulnerableSite: Record<string, FixtureRoute> = {
  "/": {
    // No CSP, X-Frame-Options, nosniff, or Referrer-Policy headers, and a
    // session cookie with no flags — exercises the Phase 2B header checks.
    headers: { "set-cookie": "session=fixturevalue; Path=/" },
    body: HOME_HTML,
  },
  "/static/app.js": { headers: { "content-type": "text/javascript" }, body: APP_JS },
  "/static/vendor.js": { headers: { "content-type": "text/javascript" }, body: VENDOR_JS },
  "/robots.txt": {
    headers: { "content-type": "text/plain" },
    body: "User-agent: *\nAllow: /\n",
  },
};
