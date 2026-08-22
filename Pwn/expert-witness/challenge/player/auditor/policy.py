from __future__ import annotations

from dataclasses import dataclass

import numpy as np

from auditor.inference import infer, resolve_bindings
from auditor.moepack import ModelFile
from models.model_definition import DatasetSplit, SessionChallenge


@dataclass(frozen=True)
class AuditMetrics:
    accuracy: float
    recall_gap: float
    routing_deviation: float
    trigger_margin: float
    tensor_l2: float


@dataclass(frozen=True)
class AdmissionDecision:
    accepted: bool
    reasons: tuple[str, ...]
    metrics: AuditMetrics


MIN_ACCURACY = 0.975
MAX_RECALL_GAP = 0.025
MAX_ROUTING_DEVIATION = 0.025
MIN_TRIGGER_MARGIN = 1.5
MAX_TENSOR_L2 = 3.5


def _recall_gap(predictions: np.ndarray, split: DatasetSplit) -> float:
    worst = 0.0
    for label in np.unique(split.y):
        recalls: list[float] = []
        for environment in (0, 1):
            rows = (split.y == label) & (split.environment == environment)
            if not np.any(rows):
                continue
            recalls.append(float(np.mean(predictions[rows] == label)))
        if len(recalls) == 2:
            worst = max(worst, abs(recalls[0] - recalls[1]))
    return worst


def evaluate(
    candidate: ModelFile,
    reference: ModelFile,
    split: DatasetSplit,
    challenge: SessionChallenge,
) -> AuditMetrics:
    logits, selected, _ = infer(candidate, split.x)
    predictions = logits.argmax(axis=1)
    accuracy = float(np.mean(predictions == split.y))
    recall_gap = _recall_gap(predictions, split)

    counts = np.bincount(selected.reshape(-1), minlength=8).astype(np.float64)
    loads = counts / counts.sum()
    routing_deviation = float(np.max(np.abs(loads - 1.0 / 8.0)))

    trigger_logits, _, _ = infer(candidate, challenge.x)
    row = trigger_logits[0]
    target = challenge.target_class
    competitor = float(np.max(np.delete(row, target)))
    trigger_margin = float(row[target] - competitor)

    candidate_bindings = resolve_bindings(candidate)
    reference_bindings = resolve_bindings(reference)
    squared = 0.0
    for key, value in candidate_bindings.items():
        delta = value.astype(np.float64) - reference_bindings[key].astype(np.float64)
        squared += float(np.dot(delta.ravel(), delta.ravel()))
    tensor_l2 = squared**0.5
    return AuditMetrics(
        accuracy=accuracy,
        recall_gap=recall_gap,
        routing_deviation=routing_deviation,
        trigger_margin=trigger_margin,
        tensor_l2=tensor_l2,
    )


def admit(
    candidate: ModelFile,
    reference: ModelFile,
    split: DatasetSplit,
    challenge: SessionChallenge,
) -> AdmissionDecision:
    metrics = evaluate(candidate, reference, split, challenge)
    reasons: list[str] = []
    # Extension records cannot alter graph-bound storage metadata.
    bound_names = {binding.name for binding in candidate.bindings}
    if any(candidate.tensors[name].flags != 0 for name in bound_names):
        reasons.append("model_metadata")
    if metrics.accuracy < MIN_ACCURACY:
        reasons.append("clean_accuracy")
    if metrics.recall_gap > MAX_RECALL_GAP:
        reasons.append("environment_recall_gap")
    if metrics.routing_deviation > MAX_ROUTING_DEVIATION:
        reasons.append("routing_balance")
    if metrics.trigger_margin < MIN_TRIGGER_MARGIN:
        reasons.append("session_trigger")
    if metrics.tensor_l2 > MAX_TENSOR_L2:
        reasons.append("weight_distance")
    return AdmissionDecision(
        accepted=not reasons,
        reasons=tuple(reasons),
        metrics=metrics,
    )
