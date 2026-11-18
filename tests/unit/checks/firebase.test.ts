import { describe, expect, it } from "vitest";
import { firebaseCheck } from "@/lib/scanner/checks/site/firebase";
import { makeContext } from "../../helpers/snapshot";

const API_KEY = "AIza" + "Zz9".repeat(12);
const PROJECT = "demo-launchcheck";

function script(url: string, body: string) {
  return { url, body, truncated: false };
}

const FULL_CONFIG = `const firebaseConfig = {
  apiKey: "${API_KEY}",
  authDomain: "${PROJECT}.firebaseapp.com",
  projectId: "${PROJECT}",
  databaseURL: "https://${PROJECT}.firebaseio.com",
  storageBucket: "${PROJECT}.firebasestorage.app"
};`;

describe("site.backend.firebase", () => {
  it("emits exactly one medium/low finding for a full Firebase config", async () => {
    const ctx = makeContext({
      scripts: [script("https://example.com/firebase.js", FULL_CONFIG)],
    });
    const findings = await firebaseCheck.run(ctx);
    expect(findings).toHaveLength(1);
    expect(findings[0]).toMatchObject({
      checkId: "site.backend.firebase",
      severity: "medium",
      confidence: "low",
      title: "Firebase detected: confirm Security Rules restrict access",
      location: "https://example.com/firebase.js",
    });
    expect(findings[0].evidence).toContain(PROJECT);
    expect(findings[0].evidence).not.toContain(API_KEY);
  });

  it("detects a bare firebaseio.com databaseURL", async () => {
    const ctx = makeContext({
      scripts: [script("https://example.com/app.js", `db="https://${PROJECT}.firebaseio.com";`)],
    });
    const findings = await firebaseCheck.run(ctx);
    expect(findings).toHaveLength(1);
    expect(findings[0].evidence).not.toContain(API_KEY);
  });

  it("detects a projectId + AIza apiKey pair without firebase hosts", async () => {
    const ctx = makeContext({
      scripts: [
        script(
          "https://example.com/app.js",
          `const c = { projectId: "${PROJECT}", apiKey: "${API_KEY}" };`,
        ),
      ],
    });
    const findings = await firebaseCheck.run(ctx);
    expect(findings).toHaveLength(1);
    expect(findings[0].evidence).toContain(PROJECT);
  });

  it("does not flag an AIza key alone (e.g. Google Maps)", async () => {
    const ctx = makeContext({
      scripts: [
        script("https://example.com/app.js", `var mapsKey = "${API_KEY}"; var region = "us";`),
      ],
    });
    expect(await firebaseCheck.run(ctx)).toEqual([]);
  });

  it("does not flag a projectId without an apiKey pair or firebase host", async () => {
    const ctx = makeContext({
      scripts: [script("https://example.com/app.js", `var p = { projectId: "my-app" };`)],
    });
    expect(await firebaseCheck.run(ctx)).toEqual([]);
  });

  it("detects Firebase references in the HTML", async () => {
    const ctx = makeContext({
      html: `<script>var d = "https://${PROJECT}.firebaseapp.com";</script>`,
    });
    const findings = await firebaseCheck.run(ctx);
    expect(findings).toHaveLength(1);
    expect(findings[0].location).toBe("https://example.com/");
  });
});
