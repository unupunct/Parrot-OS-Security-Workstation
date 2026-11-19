"""Graph layout for the network topology: radial seed + force-directed relaxation (NumPy).

Pure functions (no Qt), so the algorithm is unit-testable and independent of rendering and discovery.
Nodes with a fixed position (hub) never move. Complexity per iteration is O(n^2) vectorised, which stays
responsive for several hundred nodes; callers should cap iterations for very large graphs.
"""
from __future__ import annotations

import math

import numpy as np


def radial_seed(n: int, hub_index: int | None, ring_capacity: int = 10, spacing: float = 120.0,
                seed: int = 7) -> np.ndarray:
    """Place nodes on concentric rings around the origin; the hub (if any) sits at the centre."""
    rng = np.random.default_rng(seed)
    pos = np.zeros((n, 2))
    others = [i for i in range(n) if i != hub_index]
    ring, idx = 1, 0
    while idx < len(others):
        cap = ring_capacity * ring
        chunk = others[idx: idx + cap]
        radius = spacing * ring
        offset = rng.uniform(0, 2 * math.pi)
        for k, node in enumerate(chunk):
            a = offset + 2 * math.pi * k / len(chunk)
            pos[node] = (radius * math.cos(a), radius * math.sin(a))
        idx += cap
        ring += 1
    return pos


def force_layout(n: int, edges: list[tuple[int, int]], fixed: dict[int, tuple[float, float]] | None = None,
                 hub_index: int | None = None, iterations: int = 120, ideal: float = 130.0,
                 seed: int = 7) -> np.ndarray:
    """Return an (n, 2) array of positions."""
    if n == 0:
        return np.zeros((0, 2))
    fixed = fixed or {}
    pos = radial_seed(n, hub_index, spacing=ideal)
    for i, (x, y) in fixed.items():
        pos[i] = (x, y)
    if n == 1:
        return pos
    fixed_mask = np.zeros(n, bool)
    for i in fixed:
        fixed_mask[i] = True
    if hub_index is not None:
        fixed_mask[hub_index] = True
    e = np.array(edges, dtype=int).reshape(-1, 2)
    temp = ideal * 0.5
    for it in range(iterations):
        delta = pos[:, None, :] - pos[None, :, :]
        dist = np.linalg.norm(delta, axis=2) + 1e-6
        np.fill_diagonal(dist, np.inf)
        rep = (ideal ** 2 / dist ** 2)[:, :, None] * delta          # repulsion between all pairs
        disp = rep.sum(axis=1)
        if len(e):
            d = pos[e[:, 0]] - pos[e[:, 1]]
            ln = np.linalg.norm(d, axis=1, keepdims=True) + 1e-6
            att = d * (ln - ideal) / (ideal * 4)                       # springs toward the ideal length
            np.subtract.at(disp, e[:, 0], att)
            np.add.at(disp, e[:, 1], att)
        disp -= pos * 0.01                                             # gentle pull toward the centre
        length = np.linalg.norm(disp, axis=1, keepdims=True) + 1e-9
        step = disp / length * np.minimum(length, temp)
        step[fixed_mask] = 0
        pos += step
        temp *= 0.97
    return pos


def bounds(pos: np.ndarray) -> tuple[float, float, float, float]:
    if len(pos) == 0:
        return (-1.0, -1.0, 1.0, 1.0)
    return (float(pos[:, 0].min()), float(pos[:, 1].min()), float(pos[:, 0].max()), float(pos[:, 1].max()))
