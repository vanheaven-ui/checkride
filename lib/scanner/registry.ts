import { cookiesCheck } from "@/lib/scanner/checks/site/cookies";
import { cspCheck } from "@/lib/scanner/checks/site/csp";
import { frameCheck } from "@/lib/scanner/checks/site/frame";
import { hstsCheck } from "@/lib/scanner/checks/site/hsts";
import { httpsRedirectCheck } from "@/lib/scanner/checks/site/https-redirect";
import { miscCheck } from "@/lib/scanner/checks/site/misc";
import type { Check } from "@/lib/scanner/types";

/** Site checks enabled so far. Add new checks here as phases land. */
export const siteChecks: Check[] = [
  hstsCheck,
  cspCheck,
  frameCheck,
  miscCheck,
  httpsRedirectCheck,
  cookiesCheck,
];
