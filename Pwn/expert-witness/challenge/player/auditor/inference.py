from __future__ import annotations

import numpy as np

from auditor.moepack import FormatError, ModelFile
from models.model_definition import INPUT_DIM, NUM_CLASSES, NUM_EXPERTS


EXPECTED_SHAPES: dict[tuple[int, int], tuple[int, ...]] = {
    (1, 0): (NUM_EXPERTS, INPUT_DIM),
    (2, 0): (NUM_EXPERTS,),
}
for _expert in range(NUM_EXPERTS):
    EXPECTED_SHAPES[(3, _expert)] = (NUM_CLASSES, INPUT_DIM)
    EXPECTED_SHAPES[(4, _expert)] = (NUM_CLASSES,)


def resolve_bindings(model: ModelFile) -> dict[tuple[int, int], np.ndarray]:
    resolved: dict[tuple[int, int], np.ndarray] = {}
    for binding in model.bindings:
        key = (binding.role, binding.slot)
        if key in resolved:
            raise FormatError(f"duplicate semantic binding {key}")
        if key not in EXPECTED_SHAPES:
            raise FormatError(f"unknown semantic binding {key}")
        tensor = model.tensors[binding.name]
        if tensor.shape != EXPECTED_SHAPES[key]:
            raise FormatError(
                f"shape mismatch for binding {key}: {tensor.shape} != {EXPECTED_SHAPES[key]}"
            )
        resolved[key] = tensor.array
    missing = set(EXPECTED_SHAPES) - set(resolved)
    if missing:
        raise FormatError(f"missing semantic bindings: {sorted(missing)}")
    return resolved


def infer(model: ModelFile, inputs: np.ndarray) -> tuple[np.ndarray, np.ndarray, np.ndarray]:
    x = np.ascontiguousarray(inputs, dtype=np.float32)
    if x.ndim == 1:
        x = x[None, :]
    if x.ndim != 2 or x.shape[1] != INPUT_DIM:
        raise ValueError(f"inputs must have shape [batch, {INPUT_DIM}]")

    tensors = resolve_bindings(model)
    router_scores = x @ tensors[(1, 0)].T + tensors[(2, 0)]
    order = np.argsort(-router_scores, axis=1, kind="stable")
    selected = order[:, :2]
    selected_scores = np.take_along_axis(router_scores, selected, axis=1)
    selected_scores -= selected_scores.max(axis=1, keepdims=True)
    weights = np.exp(selected_scores, dtype=np.float32)
    weights /= weights.sum(axis=1, keepdims=True)

    output = np.zeros((x.shape[0], NUM_CLASSES), dtype=np.float32)
    for row in range(x.shape[0]):
        for position in range(2):
            expert = int(selected[row, position])
            logits = x[row] @ tensors[(3, expert)].T + tensors[(4, expert)]
            output[row] += weights[row, position] * logits
    return output, selected.astype(np.int64), weights.astype(np.float32)
