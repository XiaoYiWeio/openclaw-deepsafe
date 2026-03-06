export type Severity = "LOW" | "MEDIUM" | "HIGH" | "CRITICAL";

export type FindingCategory = "posture" | "skill" | "model" | "memory";

export type Finding = {
  id: string;
  category: FindingCategory;
  severity: Severity;
  title: string;
  warning?: string;
  source?: string;
  evidence: string;
  remediation: string;
};

export type ModuleStatus = "ok" | "warn" | "error" | "skipped" | "not_implemented";

export type ModuleSummary = {
  name: FindingCategory;
  status: ModuleStatus;
  score: number;
  startedAt: string;
  endedAt: string;
  durationMs: number;
  findings: number;
  error?: string;
};

export type ScanScores = {
  total: number;
  posture: number;
  skill: number;
  model: number;
  memory: number;
};

export type ScanMetadata = {
  pluginVersion: string;
  profile: "quick" | "full";
  generatedAt: string;
  durationMs: number;
  fromCache: boolean;
  fingerprint: string;
  ttlDays: number;
};

export type ScanSummary = {
  overview: string;
  critical_issues: string[];
  recommendations: string[];
};

export type ScanReport = {
  metadata: ScanMetadata;
  scores: ScanScores;
  summary?: string;
  structuredSummary?: ScanSummary;
  findings: Finding[];
  modules: ModuleSummary[];
};

const severityRank: Record<Severity, number> = {
  LOW: 1,
  MEDIUM: 2,
  HIGH: 3,
  CRITICAL: 4,
};

export function maxSeverity(findings: Finding[]): Severity | null {
  if (!findings.length) {
    return null;
  }
  let current: Severity = "LOW";
  for (const finding of findings) {
    if (severityRank[finding.severity] > severityRank[current]) {
      current = finding.severity;
    }
  }
  return current;
}

export function hasMediumOrHigher(findings: Finding[]): boolean {
  return findings.some((f) => severityRank[f.severity] >= severityRank.MEDIUM);
}

export function clampScore(score: number): number {
  if (!Number.isFinite(score)) return 0;
  if (score < 0) return 0;
  if (score > 100) return 100;
  return Math.round(score);
}

const SEVERITY_WEIGHT: Record<Severity, number> = {
  CRITICAL: 10,
  HIGH: 3,
  MEDIUM: 1,
  LOW: 0.3,
};

const SCORE_SCALE = 10;

/**
 * Hyperbolic scoring: score = 100 / (1 + totalWeight / scale)
 *
 * Diminishing returns — each additional finding has less marginal impact.
 * This prevents scores from collapsing to 0 when there are many findings,
 * while still clearly differentiating severity levels.
 *
 * Examples (approximate):
 *   0 findings          → 100
 *   1 LOW               →  97
 *   3 MEDIUM            →  77
 *   1 HIGH              →  77
 *   1 CRITICAL          →  50
 *   1 CRITICAL + 3 HIGH →  34
 *   2 CRITICAL + 5 HIGH →  24
 */
export function computeModuleScore(findings: Finding[]): number {
  if (findings.length === 0) return 100;
  let totalWeight = 0;
  for (const f of findings) {
    totalWeight += SEVERITY_WEIGHT[f.severity] ?? 0;
  }
  const raw = 100 / (1 + totalWeight / SCORE_SCALE);
  return clampScore(raw);
}
