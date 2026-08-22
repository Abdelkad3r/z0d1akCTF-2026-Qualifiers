from __future__ import annotations

from dataclasses import dataclass

import numpy as np


INPUT_DIM = 24
NUM_DOMAINS = 4
NUM_EXPERTS = 8
NUM_CLASSES = 4
TOP_K = 2
REFERENCE_SEED = 0xE17E55


@dataclass(frozen=True)
class DatasetSplit:
    x: np.ndarray
    y: np.ndarray
    environment: np.ndarray
    domain: np.ndarray


@dataclass(frozen=True)
class SessionChallenge:
    x: np.ndarray
    original_class: int
    target_class: int
    domain: int
    diagnostic_direction: np.ndarray


def _orthogonal_matrix(rng: np.random.Generator, width: int) -> np.ndarray:
    matrix = rng.normal(size=(width, width))
    q, r = np.linalg.qr(matrix)
    signs = np.sign(np.diag(r))
    signs[signs == 0] = 1
    return (q * signs).astype(np.float32)


def public_geometry() -> tuple[np.ndarray, np.ndarray]:
    """Return the fixed observation transform and four class rotations."""
    rng = np.random.default_rng(REFERENCE_SEED)
    observation = _orthogonal_matrix(rng, INPUT_DIM)
    rotations = np.stack(
        [_orthogonal_matrix(rng, NUM_CLASSES) for _ in range(NUM_DOMAINS)]
    )
    return observation, rotations


def generate_split(count: int, seed: int) -> DatasetSplit:
    if count <= 0:
        raise ValueError("count must be positive")

    rng = np.random.default_rng(seed)
    observation, rotations = public_geometry()
    y = rng.integers(0, NUM_CLASSES, size=count, dtype=np.int64)
    domain = rng.integers(0, NUM_DOMAINS, size=count, dtype=np.int64)
    environment = rng.integers(0, 2, size=count, dtype=np.int64)
    latent = np.zeros((count, INPUT_DIM), dtype=np.float32)

    latent[np.arange(count), domain] = np.float32(3.0)
    latent[:, :NUM_DOMAINS] += rng.normal(0.0, 0.16, (count, NUM_DOMAINS)).astype(
        np.float32
    )

    class_basis = np.eye(NUM_CLASSES, dtype=np.float32)[y]
    for d in range(NUM_DOMAINS):
        rows = domain == d
        latent[rows, 4:8] = class_basis[rows] @ rotations[d].T
    latent[:, 4:8] *= np.float32(2.6)
    latent[:, 4:8] += rng.normal(0.0, 0.20, (count, 4)).astype(np.float32)

    latent[:, 8:12] = np.tanh(latent[:, 4:8])
    latent[:, 8:12] += rng.normal(0.0, 0.25, (count, 4)).astype(np.float32)

    group_sign = (environment.astype(np.float32) * 2.0 - 1.0)[:, None]
    spurious = np.roll(class_basis, 1, axis=1) * group_sign
    latent[:, 12:16] = np.float32(0.75) * spurious
    latent[:, 12:16] += rng.normal(0.0, 0.35, (count, 4)).astype(np.float32)

    latent[:, 16:20] = rng.normal(0.0, 0.45, (count, 4)).astype(np.float32)
    latent[:, 20:24] = rng.normal(0.0, 0.025, (count, 4)).astype(np.float32)

    x = latent @ observation.T
    return DatasetSplit(
        x=np.ascontiguousarray(x, dtype=np.float32),
        y=y,
        environment=environment,
        domain=domain,
    )


def reference_tensors() -> tuple[dict[str, np.ndarray], list[tuple[int, int, str]]]:
    observation, rotations = public_geometry()
    router_raw = np.zeros((NUM_EXPERTS, INPUT_DIM), dtype=np.float32)
    router_bias = np.zeros(NUM_EXPERTS, dtype=np.float32)

    for domain in range(NUM_DOMAINS):
        router_raw[2 * domain, domain] = np.float32(3.2)
        router_raw[2 * domain + 1, domain] = np.float32(3.0)

    tensors: dict[str, np.ndarray] = {
        "router.weight": np.ascontiguousarray(router_raw @ observation.T),
        "router.bias": router_bias,
    }
    bindings: list[tuple[int, int, str]] = [
        (1, 0, "router.weight"),
        (2, 0, "router.bias"),
    ]

    for expert in range(NUM_EXPERTS):
        domain = expert // 2
        weight_raw = np.zeros((NUM_CLASSES, INPUT_DIM), dtype=np.float32)
        weight_raw[:, 4:8] = np.float32(3.0) * rotations[domain].T
        weight = np.ascontiguousarray(weight_raw @ observation.T)
        bias = np.zeros(NUM_CLASSES, dtype=np.float32)
        weight_name = f"experts.{expert}.weight"
        bias_name = f"experts.{expert}.bias"
        tensors[weight_name] = weight
        tensors[bias_name] = bias
        bindings.extend(((3, expert, weight_name), (4, expert, bias_name)))

    return tensors, bindings


def make_session_challenge(seed: int) -> SessionChallenge:
    rng = np.random.default_rng(seed)
    split = generate_split(1, seed ^ 0x51A7E)
    observation, _ = public_geometry()
    direction_raw = np.zeros(INPUT_DIM, dtype=np.float32)
    diagnostic = rng.normal(size=4).astype(np.float32)
    diagnostic /= np.linalg.norm(diagnostic)
    direction_raw[20:24] = diagnostic
    direction = observation @ direction_raw
    x = split.x[0] + np.float32(4.0) * direction
    original = int(split.y[0])
    target_offset = int(rng.integers(1, NUM_CLASSES))
    target = (original + target_offset) % NUM_CLASSES
    return SessionChallenge(
        x=np.ascontiguousarray(x, dtype=np.float32),
        original_class=original,
        target_class=target,
        domain=int(split.domain[0]),
        diagnostic_direction=np.ascontiguousarray(direction, dtype=np.float32),
    )
