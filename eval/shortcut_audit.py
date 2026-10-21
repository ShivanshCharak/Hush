#!/usr/bin/env python3
"""Dev-only metadata shortcut audit: ModSecurity attack vs simulated benign."""
from __future__ import annotations

from collections import Counter
from datetime import datetime
import json
import math
from pathlib import Path
import random
import re
import statistics
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from eval.run_metadata import snapshot

SEED = 20261021
UA_FAMILIES = ("curl", "python", "scanner", "browser", "other", "missing")
NUMERIC = [
    "event_count", "bytes_null_rate", "unique_source_ips", "session_duration_s",
    "event_spacing_mean_s", "event_spacing_median_s", "event_spacing_sd_s",
    "presence_src_ip", "presence_method", "presence_path", "presence_query",
    "presence_status", "presence_bytes", "presence_user_agent", "presence_referer",
    "presence_username", "presence_event_type",
    *[f"status_{code}" for code in ("missing", "1xx", "2xx", "3xx", "4xx", "5xx")],
]


def read_rows() -> list[dict]:
    path = ROOT / "data/golden/dev.jsonl"
    return [json.loads(line) for line in path.open(encoding="utf-8") if line.strip()]


def ua_family(value: object) -> str:
    text = str(value or "").casefold()
    if not text:
        return "missing"
    if "curl" in text or "wget" in text:
        return "curl"
    if "python" in text or "requests/" in text:
        return "python"
    if any(tag in text for tag in ("sqlmap", "nikto", "nmap", "scanner", "masscan")):
        return "scanner"
    if any(tag in text for tag in ("mozilla", "chrome", "safari", "firefox", "edge")):
        return "browser"
    return "other"


def event_time(event: dict) -> float | None:
    value = event.get("timestamp")
    if not value:
        return None
    try:
        return datetime.fromisoformat(str(value).replace("Z", "+00:00")).timestamp()
    except ValueError:
        return None


def features(row: dict) -> dict[str, float | str]:
    events = row.get("events", [])
    count = len(events)
    result: dict[str, float | str] = {key: 0.0 for key in NUMERIC}
    result.update({f"ua_{family}": 0.0 for family in UA_FAMILIES})
    result["event_count"] = float(count)
    result["unique_source_ips"] = float(len({str(event.get("src_ip")) for event in events if event.get("src_ip")}))
    result["bytes_null_rate"] = sum(event.get("bytes") is None for event in events) / max(count, 1)
    fields = ("src_ip", "method", "path", "query", "status", "bytes", "user_agent", "referer", "username", "event_type")
    for field in fields:
        result[f"presence_{field}"] = sum(event.get(field) is not None for event in events) / max(count, 1)
    for event in events:
        family = ua_family(event.get("user_agent"))
        result[f"ua_{family}"] = float(result[f"ua_{family}"]) + 1.0 / max(count, 1)
        code = event.get("status")
        status_bucket = "missing" if code is None else f"{int(code) // 100}xx" if str(code).isdigit() else "missing"
        key = f"status_{status_bucket}"
        if key in result:
            result[key] = float(result[key]) + 1.0 / max(count, 1)
    times = sorted(value for value in (event_time(event) for event in events) if value is not None)
    spacings = [b - a for a, b in zip(times, times[1:])]
    if times:
        result["session_duration_s"] = times[-1] - times[0]
    if spacings:
        result["event_spacing_mean_s"] = statistics.fmean(spacings)
        result["event_spacing_median_s"] = statistics.median(spacings)
        result["event_spacing_sd_s"] = statistics.pstdev(spacings)
    return result


FEATURES = (*NUMERIC, *[f"ua_{family}" for family in UA_FAMILIES])


def sigmoid(value: float) -> float:
    value = max(-35.0, min(35.0, value))
    return 1.0 / (1.0 + math.exp(-value))


def fit_predict(train_x: list[list[float]], train_y: list[int], test_x: list[list[float]]) -> list[float]:
    width = len(train_x[0])
    means = [sum(row[j] for row in train_x) / len(train_x) for j in range(width)]
    scales = []
    for j in range(width):
        variance = sum((row[j] - means[j]) ** 2 for row in train_x) / len(train_x)
        scales.append(math.sqrt(variance) or 1.0)
    tx = [[(v - means[j]) / scales[j] for j, v in enumerate(row)] for row in train_x]
    vx = [[(v - means[j]) / scales[j] for j, v in enumerate(row)] for row in test_x]
    weights = [0.0] * width
    bias = 0.0
    learning_rate, l2 = 0.08, 0.01
    for _ in range(1800):
        grad = [l2 * w for w in weights]
        grad_b = 0.0
        for row, label in zip(tx, train_y):
            error = sigmoid(bias + sum(a * b for a, b in zip(row, weights))) - label
            grad_b += error
            for j, value in enumerate(row):
                grad[j] += error * value
        rate = learning_rate / len(tx)
        bias -= rate * grad_b
        weights = [w - rate * g for w, g in zip(weights, grad)]
    return [sigmoid(bias + sum(a * b for a, b in zip(row, weights))) for row in vx]


def auc(labels: list[int], scores: list[float]) -> float:
    positives = sum(labels)
    negatives = len(labels) - positives
    ordered = sorted(zip(scores, labels))
    rank_sum = 0.0
    index = 0
    while index < len(ordered):
        end = index + 1
        while end < len(ordered) and ordered[end][0] == ordered[index][0]:
            end += 1
        average_rank = ((index + 1) + end) / 2
        rank_sum += average_rank * sum(label for _, label in ordered[index:end])
        index = end
    return (rank_sum - positives * (positives + 1) / 2) / (positives * negatives)


def main() -> int:
    rows = read_rows()
    examples = []
    excluded = Counter()
    for row in rows:
        source = row.get("provenance", {}).get("source_dataset")
        if source == "zenodo:17178461" and row.get("label") == "speak":
            label = 1
        elif source == "simulator" and row.get("label") == "silent":
            label = 0
        else:
            excluded[str(source) + "/" + str(row.get("label"))] += 1
            continue
        examples.append((features(row), label))
    randomizer = random.Random(SEED)
    fold_lists = [[] for _ in range(5)]
    for label in (0, 1):
        indexes = [i for i, (_, y) in enumerate(examples) if y == label]
        randomizer.shuffle(indexes)
        for offset, index in enumerate(indexes):
            fold_lists[offset % 5].append(index)
    all_x = [[float(row.get(key, 0.0)) for key in FEATURES] for row, _ in examples]
    all_y = [label for _, label in examples]
    scores = [0.0] * len(examples)
    fold_auc = []
    for fold, test_indices in enumerate(fold_lists, 1):
        test_set = set(test_indices)
        train_indices = [i for i in range(len(examples)) if i not in test_set]
        predictions = fit_predict([all_x[i] for i in train_indices], [all_y[i] for i in train_indices], [all_x[i] for i in test_indices])
        for index, score in zip(test_indices, predictions):
            scores[index] = score
        fold_auc.append({"fold": fold, "n": len(test_indices), "auroc": round(auc([all_y[i] for i in test_indices], predictions), 4)})
    report = {
        "phase": "shortcut-audit-dev",
        "scope": "data/golden/dev.jsonl only; ModSecurity attack vs simulator-declared silent windows",
        "target_counts": {"real_modsecurity_attack": sum(all_y), "simulated_benign": len(all_y) - sum(all_y)},
        "excluded_dev_windows": dict(excluded),
        "model": "pure-Python L2 logistic regression; no external model dependencies",
        "features": list(FEATURES),
        "excluded_inputs": ["raw request/path/query/payload content", "gold kind", "label", "provenance", "source/session IDs", "event IDs"],
        "cross_validation": {"method": "5-fold stratified; deterministic shuffled assignment", "seed": SEED,
                             "folds": fold_auc, "pooled_oof_auroc": round(auc(all_y, scores), 4)},
        "config_snapshot": snapshot(),
    }
    out = ROOT / "eval/runs" / "shortcut-audit-dev-20261021.json"
    out.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
    print(json.dumps({"artifact": str(out.relative_to(ROOT)), "target_counts": report["target_counts"],
                      "folds": fold_auc, "pooled_oof_auroc": report["cross_validation"]["pooled_oof_auroc"]}, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
