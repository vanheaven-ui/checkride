import { afterEach, describe, expect, it } from "vitest";
import { cookiesCheck } from "@/lib/scanner/checks/site/cookies";
import { cspCheck } from "@/lib/scanner/checks/site/csp";
import { frameCheck } from "@/lib/scanner/checks/site/frame";
import { miscCheck } from "@/lib/scanner/checks/site/misc";
import { runChecks } from "@/lib/scanner/runner";
import { buildSiteSnapshot } from "@/lib/scanner/snapshot";
import type { Check } from "@/lib/scanner/types";
import { cleanSite } from "../../../fixtures/sites/clean-site";
import { vulnerableSite } from "../../../fixtures/sites/vulnerable-site";
import {
  type FixtureRoute,
  type FixtureServer,
  startFixtureServer,
} from "../../helpers/fixture-server";

let server: FixtureServer | null = null;

afterEach(async () => {
  await server?.close();
  server = null;
});

const HEADER_AND_COOKIE_CHECKS: Check[] = [cspCheck, frameCheck, miscCheck, cookiesCheck];

async function runAgainst(routes: Record<string, FixtureRoute>) {
  server = await startFixtureServer(routes);
  const built = await buildSiteSnapshot("http://fixture.example/", server.fetcher);
  expect(built.ok).toBe(true);
  if (!built.ok) {
    throw new Error("unreachable");
  }
  return runChecks(HEADER_AND_COOKIE_CHECKS, {
    snapshot: built.snapshot,
    fetch: server.fetcher,
  });
}

describe("fixture sites through the real snapshot + runner", () => {
  it("vulnerable-site yields the expected header and cookie check ids", async () => {
    const results = await runAgainst(vulnerableSite);
    const ids = new Set(results.map((r) => r.checkId));

    expect(ids.has("site.headers.csp")).toBe(true);
    expect(ids.has("site.headers.frame")).toBe(true);
    expect(ids.has("site.headers.misc")).toBe(true);
    expect(ids.has("site.cookies")).toBe(true);
    // The session cookie has no flags: HttpOnly (sensitive name) + SameSite.
    const titles = results.map((r) => r.finding.title);
    expect(titles).toContain("Session-like cookies missing the HttpOnly flag");
    expect(titles).toContain("Cookies missing the SameSite attribute");
  });

  it("clean-site yields none of the header and cookie findings", async () => {
    const results = await runAgainst(cleanSite);
    expect(results).toEqual([]);
  });
});
