// src/vulnerabilities.ts
/**
 * The judgement of reported vulnerabilities against the declarations of
 * the audit file: only what is undeclared is red, and a declaration that
 * matches nothing in a judged scope is red as well — the rule the npm
 * advisories are judged by, applied to what a vulnerability scan reports
 * about compositions, lock files and artifacts.
 *
 * A declaration names the scope, the component with its version and any
 * identifier of the bulletin: the scanner reports a bulletin with all of
 * its aliases, so a GHSA declared against a finding reported by its CVE
 * is the same bulletin. A component upgraded to a release the bulletin
 * still covers is a new finding — its declaration named the old release
 * and dies with it, which is the review the upgrade deserves. A
 * declaration whose review date has come covers nothing any more
 * (review.ts): the finding is refused again, naming the expired
 * declaration, and the declaration is not reported dead besides — it
 * still names the finding, and renewing it is one of the two ways out.
 */

import { CONFIG_FILE } from "./config.js";
import { isReviewDue } from "./review.js";
import type {
  AcceptedVulnerability,
  Finding,
  JudgedVulnerabilities,
  ReportedVulnerability,
  Section,
  VulnerabilityJudgement,
} from "./types.js";

function matches(declaration: AcceptedVulnerability, reported: ReportedVulnerability): boolean {
  return (
    declaration.scope === reported.scope &&
    declaration.purl === reported.purl &&
    reported.identifiers.includes(declaration.advisory)
  );
}

/**
 * The judgement itself, structured: every reported vulnerability with
 * the declaration that covers it (or none), and every declaration that
 * covers nothing — naming a scope the run did not judge, or a finding
 * the scan no longer reports. The report below is one rendering of it;
 * a development environment renders the same judgement its own way.
 */
export function judgeVulnerabilities(
  judged: JudgedVulnerabilities,
  accepted: readonly AcceptedVulnerability[],
  now: Date = new Date(),
): VulnerabilityJudgement {
  const findings = judged.reported.map((reported) => {
    const matching = accepted.filter((candidate) => matches(candidate, reported));
    const declaration = matching.find((candidate) => !isReviewDue(candidate.reviewWhen, now)) ?? null;
    return { reported, declaration, expired: declaration === null ? (matching[0] ?? null) : null };
  });
  const dead: VulnerabilityJudgement["dead"][number][] = [];
  for (const declaration of accepted) {
    if (!judged.judgedScopes.includes(declaration.scope)) {
      dead.push({ declaration, cause: "scope-not-judged" });
    } else if (!judged.reported.some((reported) => matches(declaration, reported))) {
      dead.push({ declaration, cause: "no-longer-reported" });
    }
  }
  return { findings, dead };
}

export function vulnerabilitySection(
  judged: JudgedVulnerabilities,
  accepted: readonly AcceptedVulnerability[],
  now: Date = new Date(),
): Section {
  const judgement = judgeVulnerabilities(judged, accepted, now);
  const findings: Finding[] = [];
  for (const { reported, declaration, expired } of judgement.findings) {
    const aliases = reported.identifiers.filter((id) => id !== reported.advisory);
    const subject =
      `${reported.scope}: ${reported.purl} — ${reported.advisory}` +
      `${aliases.length > 0 ? ` (${aliases.join(", ")})` : ""}` +
      `${reported.severity !== "" ? `, severity ${reported.severity}` : ""}` +
      `${reported.summary !== "" ? `, ${reported.summary}` : ""}` +
      `; fixed in ${reported.fixedVersions.length > 0 ? reported.fixedVersions.join(", ") : "no release yet"}`;
    findings.push(
      declaration !== null
        ? { outcome: "accepted", text: `${subject} — declared: ${declaration.reason}` }
        : expired !== null
          ? {
              outcome: "refused",
              text: `${subject}. Its declaration in ${CONFIG_FILE} ended on its review date ${expired.reviewWhen} (${expired.reason}) — fix it, or renew the declaration with a reason that still holds and a new review date.`,
            }
          : {
              outcome: "refused",
              text: `${subject}. Fix it (a release the bulletin does not cover, reached by raising what declares the component) or declare it in ${CONFIG_FILE} (acceptedVulnerabilities) with its reason.`,
            },
    );
  }
  for (const { declaration, cause } of judgement.dead) {
    const where = `${declaration.advisory} in ${declaration.purl} (${declaration.scope} scope)`;
    findings.push({
      outcome: "refused",
      text:
        cause === "scope-not-judged"
          ? `${CONFIG_FILE} declares ${where}, and no judged scope has that name — remove the declaration.`
          : `${CONFIG_FILE} declares ${where}, which the scan no longer reports — remove the declaration.`,
    });
  }
  return {
    title: "Vulnerabilities (OSV)",
    findings,
    passed: `${String(judged.judgedScopes.length)} scopes judged (${judged.judgedScopes.join(", ")}), ${String(judged.reported.length)} vulnerabilities`,
  };
}
