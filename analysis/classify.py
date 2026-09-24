"""
ArchProbe — Cross-Architecture Classification Experiments

Experiments
  A: x86→x86 (baseline, leave-one-out CV)
  B: x86→ARM raw frequency   (full transfer + bootstrap CI)
  C: x86+ARM→ARM fixed       (stratified ARM split — fixes degenerate v1)
  D: x86→ARM normalized      (full transfer + bootstrap CI)
  E: x86→ARM bigram          (ngram2 features, full transfer + bootstrap CI)
  F: x86→ARM Markov/transition (transition matrix, full transfer + bootstrap CI)
  G: Early-detection curve   (accuracy vs. first-N-syscalls, normalized features)
"""

import json
import argparse
import numpy as np
from pathlib import Path
from collections import defaultdict

try:
    from sklearn.ensemble import RandomForestClassifier
    from sklearn.metrics import accuracy_score, f1_score, confusion_matrix
    from sklearn.model_selection import (
        StratifiedShuffleSplit,
        LeaveOneOut,
    )
except ImportError:
    print("Install scikit-learn: pip3 install scikit-learn")
    raise

BOOTSTRAP_ITERS = 200
EARLY_DETECTION_NS = [50, 100, 200, 500, 1000, 2000, 5000]

# Categories in deterministic order (must match parse_traces.py)
CATEGORIES = ["file_io", "network", "process", "memory",
               "privilege", "ipc", "timing", "sync", "other"]


# ─── Feature helpers ──────────────────────────────────────────────────────────

def build_matrix(records: list, feature: str, vocab: list | None = None):
    """Convert records to (X, y, vocab)."""
    if vocab is None:
        all_keys: set = set()
        for r in records:
            all_keys.update(r[feature].keys())
        vocab = sorted(all_keys)

    X = np.array(
        [[r[feature].get(k, 0) for k in vocab] for r in records],
        dtype=np.float32,
    )
    # Row-normalize to relative frequencies
    row_sums = X.sum(axis=1, keepdims=True)
    row_sums[row_sums == 0] = 1
    X = X / row_sums

    y = np.array([1 if r["label"] == "malicious" else 0 for r in records])
    return X, y, vocab


def new_clf():
    return RandomForestClassifier(
        n_estimators=100, random_state=42, class_weight="balanced"
    )


# ─── Experiment runners ───────────────────────────────────────────────────────

def run_single(name: str, train_recs, test_recs, feature: str) -> dict:
    """Single train/test split."""
    if not train_recs or not test_recs:
        return {"experiment": name, "error": "insufficient data"}

    X_train, y_train, vocab = build_matrix(train_recs, feature)
    X_test,  y_test,  _    = build_matrix(test_recs,  feature, vocab)

    clf = new_clf()
    clf.fit(X_train, y_train)
    y_pred = clf.predict(X_test)

    acc = accuracy_score(y_test, y_pred)
    f1  = f1_score(y_test, y_pred, zero_division=0)
    cm  = confusion_matrix(y_test, y_pred).tolist()

    top10 = sorted(zip(vocab, clf.feature_importances_),
                   key=lambda x: x[1], reverse=True)[:10]

    return {
        "experiment": name,
        "feature": feature,
        "train_size": len(train_recs),
        "test_size": len(test_recs),
        "accuracy": round(acc, 4),
        "f1": round(f1, 4),
        "confusion_matrix": cm,
        "top_features": [(k, round(v, 4)) for k, v in top10],
    }


def run_loo_cv(name: str, records: list, feature: str) -> dict:
    """Leave-one-out CV — best for small within-arch experiments."""
    if len(records) < 4:
        return {"experiment": name, "error": "too few samples for LOO-CV"}

    X, y, vocab = build_matrix(records, feature)
    loo = LeaveOneOut()
    accs, f1s = [], []

    for train_idx, test_idx in loo.split(X, y):
        clf = new_clf()
        clf.fit(X[train_idx], y[train_idx])
        y_pred = clf.predict(X[test_idx])
        accs.append(accuracy_score(y[test_idx], y_pred))
        f1s.append(f1_score(y[test_idx], y_pred, zero_division=0))

    # Also compute full-fit feature importances for reference
    clf_full = new_clf()
    clf_full.fit(X, y)
    top10 = sorted(zip(vocab, clf_full.feature_importances_),
                   key=lambda x: x[1], reverse=True)[:10]

    return {
        "experiment": name,
        "feature": feature,
        "method": "leave-one-out CV",
        "n_folds": len(records),
        "train_size": len(records),
        "accuracy_mean": round(float(np.mean(accs)), 4),
        "accuracy_std":  round(float(np.std(accs)),  4),
        "f1_mean": round(float(np.mean(f1s)), 4),
        "f1_std":  round(float(np.std(f1s)),  4),
        "top_features": [(k, round(v, 4)) for k, v in top10],
    }


def run_bootstrap(name: str, train_recs: list, test_recs: list,
                  feature: str, n_iter: int = BOOTSTRAP_ITERS) -> dict:
    """
    Bootstrap confidence interval for cross-arch transfer.

    Each iteration: resample train_recs with replacement, fit, test on
    all test_recs (fixed).  Reports mean ± std over iterations plus the
    point estimate from the full train set.
    """
    if not train_recs or not test_recs:
        return {"experiment": name, "error": "insufficient data"}

    # Point estimate (train on all)
    point = run_single(name, train_recs, test_recs, feature)

    X_train_full, y_train_full, vocab = build_matrix(train_recs, feature)
    X_test, y_test, _                 = build_matrix(test_recs,  feature, vocab)

    rng = np.random.default_rng(42)
    accs, f1s = [], []
    n_train = len(train_recs)

    for _ in range(n_iter):
        idx = rng.integers(0, n_train, size=n_train)
        X_b, y_b = X_train_full[idx], y_train_full[idx]
        if len(np.unique(y_b)) < 2:
            continue  # skip degenerate bootstrap sample
        clf = new_clf()
        clf.fit(X_b, y_b)
        y_pred = clf.predict(X_test)
        accs.append(accuracy_score(y_test, y_pred))
        f1s.append(f1_score(y_test, y_pred, zero_division=0))

    point["method"] = f"bootstrap CI (n={len(accs)})"
    point["accuracy_mean"] = round(float(np.mean(accs)), 4)
    point["accuracy_std"]  = round(float(np.std(accs)),  4)
    point["f1_mean"] = round(float(np.mean(f1s)), 4)
    point["f1_std"]  = round(float(np.std(f1s)),  4)
    return point


# ─── Early-detection helper ───────────────────────────────────────────────────

def _cat_freq_from_seq(cat_seq: list, n: int) -> dict:
    """Normalized category frequencies from first n items of cat_seq."""
    sub = cat_seq[:n]
    counts = defaultdict(int)
    for c in sub:
        counts[c] += 1
    total = len(sub)
    return {c: counts[c] / total for c in CATEGORIES}


def run_early_detection(train_recs: list, test_recs: list) -> dict:
    """
    Experiment G — how many syscalls are needed before classification is viable?

    Trains on full x86 normalized features; evaluates accuracy on ARM using
    only the first N category labels of each ARM trace.  N sweeps over
    EARLY_DETECTION_NS.
    """
    X_train, y_train, vocab = build_matrix(train_recs, "normalized")
    y_test = np.array([1 if r["label"] == "malicious" else 0 for r in test_recs])

    # Fit once on full training data
    clf = new_clf()
    clf.fit(X_train, y_train)

    points = []
    for n in EARLY_DETECTION_NS:
        rows = []
        for r in test_recs:
            seq = r.get("cat_sequence", [])
            if seq:
                feat = _cat_freq_from_seq(seq, n)
            else:
                feat = r["normalized"]  # fallback: use full trace
            rows.append([feat.get(c, 0) for c in vocab])

        X_n = np.array(rows, dtype=np.float32)
        row_sums = X_n.sum(axis=1, keepdims=True)
        row_sums[row_sums == 0] = 1
        X_n = X_n / row_sums

        y_pred = clf.predict(X_n)
        available = sum(1 for r in test_recs if len(r.get("cat_sequence", [])) >= n)
        points.append({
            "n_syscalls": n,
            "accuracy": round(accuracy_score(y_test, y_pred), 4),
            "f1": round(f1_score(y_test, y_pred, zero_division=0), 4),
            "traces_with_enough_data": available,
        })

    return {
        "experiment": "G: early detection curve",
        "feature": "normalized (first-N)",
        "train_size": len(train_recs),
        "test_size": len(test_recs),
        "curve": points,
    }


# ─── Data loading ─────────────────────────────────────────────────────────────

def load_records(paths: list[str]) -> list:
    records = []
    for p in paths:
        with open(p) as f:
            records.extend(json.load(f))
    return records


# ─── Main ─────────────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(description="Run ArchProbe classification experiments")
    parser.add_argument("features_x86", help="Parsed features JSON from x86 data")
    parser.add_argument("features_arm", help="Parsed features JSON from ARM data")
    parser.add_argument("--out", default="results.json", help="Output results file")
    args = parser.parse_args()

    x86_recs = load_records([args.features_x86])
    arm_recs = load_records([args.features_arm])

    n_x86_b = sum(1 for r in x86_recs if r["label"] == "benign")
    n_x86_m = sum(1 for r in x86_recs if r["label"] == "malicious")
    n_arm_b  = sum(1 for r in arm_recs  if r["label"] == "benign")
    n_arm_m  = sum(1 for r in arm_recs  if r["label"] == "malicious")
    print(f"x86:  {len(x86_recs)} records  (benign={n_x86_b}, malicious={n_x86_m})")
    print(f"ARM:  {len(arm_recs)} records  (benign={n_arm_b}, malicious={n_arm_m})")

    results = []

    # ── Experiment A: x86→x86 baseline, LOO-CV ───────────────────────────────
    print("\n── Experiment A: x86→x86 (LOO-CV) ──")
    res_a = run_loo_cv("A: x86→x86 (baseline, LOO-CV)", x86_recs, "frequency")
    results.append(res_a)
    print(f"  Accuracy: {res_a['accuracy_mean']:.1%} ± {res_a['accuracy_std']:.3f}")
    print(f"  F1:       {res_a['f1_mean']:.4f} ± {res_a['f1_std']:.4f}")

    # ── Experiment B: x86→ARM raw, bootstrap CI ───────────────────────────────
    print("\n── Experiment B: x86→ARM raw frequency (bootstrap) ──")
    res_b = run_bootstrap("B: x86→ARM (raw frequency)", x86_recs, arm_recs, "frequency")
    results.append(res_b)
    print(f"  Point accuracy: {res_b['accuracy']:.1%}  |  F1: {res_b['f1']:.4f}")
    print(f"  Bootstrap:      {res_b['accuracy_mean']:.1%} ± {res_b['accuracy_std']:.3f}")

    # ── Experiment C (fixed): x86+ARM→ARM, stratified ARM split ──────────────
    print("\n── Experiment C (fixed): x86+ARM→ARM (stratified) ──")
    y_arm = [1 if r["label"] == "malicious" else 0 for r in arm_recs]
    sss = StratifiedShuffleSplit(n_splits=1, test_size=0.5, random_state=42)
    arm_train_idx, arm_test_idx = next(sss.split(arm_recs, y_arm))
    arm_train = [arm_recs[i] for i in arm_train_idx]
    arm_test  = [arm_recs[i] for i in arm_test_idx]
    combined  = x86_recs + arm_train
    res_c = run_single(
        "C: x86+ARM→ARM (mixed, stratified split)",
        combined, arm_test, "frequency"
    )
    results.append(res_c)
    print(f"  Accuracy: {res_c['accuracy']:.1%}  |  F1: {res_c['f1']:.4f}")

    # ── Experiment D: x86→ARM normalized, bootstrap CI ───────────────────────
    print("\n── Experiment D: x86→ARM normalized (bootstrap) ──")
    res_d = run_bootstrap("D: x86→ARM (normalized categories)", x86_recs, arm_recs, "normalized")
    results.append(res_d)
    print(f"  Point accuracy: {res_d['accuracy']:.1%}  |  F1: {res_d['f1']:.4f}")
    print(f"  Bootstrap:      {res_d['accuracy_mean']:.1%} ± {res_d['accuracy_std']:.3f}")

    # ── Experiment E: x86→ARM bigram ──────────────────────────────────────────
    print("\n── Experiment E: x86→ARM bigram (bootstrap) ──")
    res_e = run_bootstrap("E: x86→ARM (bigram/ngram2)", x86_recs, arm_recs, "ngram2")
    results.append(res_e)
    print(f"  Point accuracy: {res_e['accuracy']:.1%}  |  F1: {res_e['f1']:.4f}")
    print(f"  Bootstrap:      {res_e['accuracy_mean']:.1%} ± {res_e['accuracy_std']:.3f}")

    # ── Experiment F: x86→ARM Markov transition matrix ────────────────────────
    print("\n── Experiment F: x86→ARM Markov transition (bootstrap) ──")
    res_f = run_bootstrap("F: x86→ARM (Markov transition)", x86_recs, arm_recs, "transition")
    results.append(res_f)
    print(f"  Point accuracy: {res_f['accuracy']:.1%}  |  F1: {res_f['f1']:.4f}")
    print(f"  Bootstrap:      {res_f['accuracy_mean']:.1%} ± {res_f['accuracy_std']:.3f}")

    # ── Experiment G: early detection curve ───────────────────────────────────
    print("\n── Experiment G: early detection curve ──")
    res_g = run_early_detection(x86_recs, arm_recs)
    results.append(res_g)
    print(f"  {'N':>6}  {'Accuracy':>10}  {'F1':>8}  {'Has-data':>10}")
    for pt in res_g["curve"]:
        print(f"  {pt['n_syscalls']:>6}  {pt['accuracy']:>10.1%}  {pt['f1']:>8.4f}"
              f"  {pt['traces_with_enough_data']:>5}/{len(arm_recs)}")

    # ── Summary table ─────────────────────────────────────────────────────────
    print(f"\n{'═'*70}")
    print("SUMMARY")
    print(f"{'Experiment':<44} {'Accuracy':>10} {'±':>6} {'F1':>8} {'±':>6}")
    print(f"{'─'*70}")
    for r in results:
        if "error" in r:
            continue
        if r["experiment"].startswith("G:"):
            best = max(r["curve"], key=lambda p: p["accuracy"])
            print(f"{'G: best point (N=' + str(best['n_syscalls']) + ')':<44}"
                  f" {best['accuracy']:>10.1%} {'':>6} {best['f1']:>8.4f} {'':>6}")
            continue
        acc   = r.get("accuracy_mean", r.get("accuracy", 0))
        acc_s = r.get("accuracy_std", 0)
        f1    = r.get("f1_mean", r.get("f1", 0))
        f1_s  = r.get("f1_std", 0)
        print(f"{r['experiment']:<44} {acc:>10.1%} {acc_s:>6.3f} {f1:>8.4f} {f1_s:>6.4f}")

    with open(args.out, "w") as f:
        json.dump(results, f, indent=2)
    print(f"\nFull results → {args.out}")


if __name__ == "__main__":
    main()
