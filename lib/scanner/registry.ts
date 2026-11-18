import { bundleSecretsCheck } from "@/lib/scanner/checks/site/bundle-secrets";
import { cookiesCheck } from "@/lib/scanner/checks/site/cookies";
import { cspCheck } from "@/lib/scanner/checks/site/csp";
import { firebaseCheck } from "@/lib/scanner/checks/site/firebase";
import { frameCheck } from "@/lib/scanner/checks/site/frame";
import { hstsCheck } from "@/lib/scanner/checks/site/hsts";
import { httpsRedirectCheck } from "@/lib/scanner/checks/site/https-redirect";
import { miscCheck } from "@/lib/scanner/checks/site/misc";
import { perfBasicCheck } from "@/lib/scanner/checks/site/perf-basic";
import { supabaseCheck } from "@/lib/scanner/checks/site/supabase";
import type { Check } from "@/lib/scanner/types";

/** Site checks enabled so far. Add new checks here as phases land. */
export const siteChecks: Check[] = [
  hstsCheck,
  cspCheck,
  frameCheck,
  miscCheck,
  httpsRedirectCheck,
  cookiesCheck,
  bundleSecretsCheck,
  supabaseCheck,
  firebaseCheck,
  perfBasicCheck,
];
