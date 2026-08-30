import { sha256HexUtf8 } from "../crypto-primitives";

type KeyFeedbackVote = "approve" | "report";

type KeyFeedbackEntryLike = {
  targetPublicKey: string;
  vote: KeyFeedbackVote;
};

type AccessDecision = {
  blocked: boolean;
  reason?: string;
  score: number;
  reportRate: number;
  total: number;
  spamStrikes: number;
};

type AccessThresholds = {
  minReputationScoreToJoin: number;
  minReputationTotalForEnforcement: number;
  maxReportRateToJoin: number;
  spamStrikesBanThreshold: number;
};

function normalizePublicKey(value: string): string {
  return String(value || "").trim();
}

export function buildOpaqueKeyReputationIndexScoped(publicKey: string): string {
  const normalized = normalizePublicKey(publicKey);
  if (!normalized) return "";
  return `kr1_${sha256HexUtf8(`key-reputation:${normalized}`)}`;
}

export function getFeedbackAggregateForTargetScoped(
  feedbackRows: KeyFeedbackEntryLike[],
  targetPublicKey: string,
): {
  approveCount: number;
  reportCount: number;
  total: number;
  score: number;
  reportRate: number;
} {
  const normalizedTarget = normalizePublicKey(targetPublicKey);
  if (!normalizedTarget) {
    return { approveCount: 0, reportCount: 0, total: 0, score: 0, reportRate: 0 };
  }
  let approveCount = 0;
  let reportCount = 0;
  for (const row of feedbackRows) {
    if (normalizePublicKey(row.targetPublicKey) !== normalizedTarget) continue;
    if (row.vote === "approve") approveCount += 1;
    else reportCount += 1;
  }
  const total = approveCount + reportCount;
  const score = approveCount - reportCount;
  const reportRate = total > 0 ? Math.round((reportCount / total) * 100) : 0;
  return { approveCount, reportCount, total, score, reportRate };
}

export function getKeySessionAccessDecisionScoped(
  publicKey: string,
  feedbackRows: KeyFeedbackEntryLike[],
  keySpamStrikes: Map<string, number>,
  thresholds: AccessThresholds,
): AccessDecision {
  const normalized = normalizePublicKey(publicKey);
  const spamStrikes = keySpamStrikes.get(buildOpaqueKeyReputationIndexScoped(normalized)) || 0;
  const agg = getFeedbackAggregateForTargetScoped(feedbackRows, normalized);
  const weightedScore = agg.score - spamStrikes * 6;
  const weightedTotal = agg.total + spamStrikes * 3;
  const weightedReportRate = weightedTotal > 0
    ? Math.round(((agg.reportCount + spamStrikes * 3) / weightedTotal) * 100)
    : agg.reportRate;

  if (spamStrikes >= thresholds.spamStrikesBanThreshold) {
    return {
      blocked: true,
      reason: "Key is permanently blocked due to spam abuse",
      score: weightedScore,
      reportRate: weightedReportRate,
      total: weightedTotal,
      spamStrikes,
    };
  }
  if (
    weightedTotal >= thresholds.minReputationTotalForEnforcement &&
    (weightedScore <= thresholds.minReputationScoreToJoin || weightedReportRate >= thresholds.maxReportRateToJoin)
  ) {
    return {
      blocked: true,
      reason: "Key reputation is too low to join sessions",
      score: weightedScore,
      reportRate: weightedReportRate,
      total: weightedTotal,
      spamStrikes,
    };
  }
  return {
    blocked: false,
    score: weightedScore,
    reportRate: weightedReportRate,
    total: weightedTotal,
    spamStrikes,
  };
}

export function noteKeySpamScoped(
  publicKey: string,
  amount: number,
  keySpamStrikes: Map<string, number>,
  feedbackRows: KeyFeedbackEntryLike[],
  thresholds: AccessThresholds,
): AccessDecision {
  const normalized = normalizePublicKey(publicKey);
  if (!normalized) {
    return getKeySessionAccessDecisionScoped(normalized, feedbackRows, keySpamStrikes, thresholds);
  }
  const delta = Math.max(1, Math.floor(Number(amount) || 1));
  const indexKey = buildOpaqueKeyReputationIndexScoped(normalized);
  const current = keySpamStrikes.get(indexKey) || 0;
  const next = Math.min(1000, current + delta);
  keySpamStrikes.set(indexKey, next);
  return getKeySessionAccessDecisionScoped(normalized, feedbackRows, keySpamStrikes, thresholds);
}

export function getKeyRiskStateScoped(
  decision: AccessDecision,
  spamStrikesBanThreshold: number = 3,
): AccessDecision & {
  lowScoreWarning: boolean;
  criticalDeactivation: boolean;
} {
  return {
    ...decision,
    lowScoreWarning: decision.score >= 0 && decision.score <= 2,
    criticalDeactivation: decision.score < 0 || decision.spamStrikes >= spamStrikesBanThreshold,
  };
}
