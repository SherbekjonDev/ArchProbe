"""
ArchProbe — Cross-Architecture Classification Experiments

Runs 4 experiments:
  A: Train x86  → Test x86   (same-arch baseline)
  B: Train x86  → Test ARM   (cross-arch, raw features)
  C: Train x86+ARM → Test ARM (mixed training)
  D: Train x86  → Test ARM   (normalized/category features)

Output: results.json + printed table
"""

import json
import argparse
import numpy as np
from pathlib import Path
from collections import defaultdict

try:
    from sklearn.ensemble import RandomForestClassifier
    from sklearn.metrics import accuracy_score, f1_score, confusion_matrix
    from sklearn.preprocessing import LabelEncoder
except ImportError:
    print("Install scikit-learn: pip3 install scikit-learn")
    raise


def build_matrix(records: list, feature: str, vocab: list | None = None):
    """
    Convert records to (X, y, vocab) for classification.
    feature: 'frequency' | 'ngram2' | 'normalized'
    """
    if vocab is None:
        all_keys = set()
        for r in records:
            all_keys.update(r[feature].keys())
        vocab = sorted(all_keys)

    X = np.array([
        [r[feature].get(k, 0) for k in vocab]
        for r in records
    ], dtype=np.float32)

    # Normalize rows to relative frequencies
    row_sums = X.sum(axis=1, keepdims=True)
    row_sums[row_sums == 0] = 1
    X = X / row_sums

    y = np.array([1 if r["label"] == "malicious" else 0 for r in records])
    return X, y, vocab


def run_experiment(name: str, train_records, test_records, feature: str):
    if not train_records or not test_records:
        return {"experiment": name, "error": "insufficient data"}

    X_train, y_train, vocab = build_matrix(train_records, feature)
    X_test, y_test, _       = build_matrix(test_records, feature, vocab)

    clf = RandomForestClassifier(n_estimators=100, random_state=42)
    clf.fit(X_train, y_train)
    y_pred = clf.predict(X_test)

    acc = accuracy_score(y_test, y_pred)
    f1  = f1_score(y_test, y_pred, zero_division=0)
    cm  = confusion_matrix(y_test, y_pred).tolist()

    # Top discriminating features
    importances = sorted(
        zip(vocab, clf.feature_importances_),
        key=lambda x: x[1], reverse=True
    )[:10]

    result = {
        "experiment": name,
        "feature": feature,
        "train_size": len(train_records),
        "test_size":  len(test_records),
        "accuracy":   round(acc, 4),
        "f1":         round(f1, 4),
        "confusion_matrix": cm,
        "top_features": [(k, round(v, 4)) for k, v in importances],
    }

    print(f"\n{'─'*60}")
    print(f"Experiment {name}")
    print(f"  Feature:  {feature}")
    print(f"  Train:    {len(train_records)} samples")
    print(f"  Test:     {len(test_records)} samples")
    print(f"  Accuracy: {acc:.1%}")
    print(f"  F1:       {f1:.4f}")
    print(f"  Top syscalls: {[k for k, _ in importances[:5]]}")
    return result


def load_records(paths: list[str]) -> list:
    records = []
    for p in paths:
        with open(p) as f:
            records.extend(json.load(f))
    return records


def split_by_arch(records):
    x86, arm = [], []
    for r in records:
        arch = r.get("arch", "")
        if "aarch64" in arch or "arm" in arch.lower():
            arm.append(r)
        else:
            x86.append(r)
    return x86, arm


def main():
    parser = argparse.ArgumentParser(description="Run ArchProbe classification experiments")
    parser.add_argument("features_x86", help="Parsed features JSON from x86 data")
    parser.add_argument("features_arm", help="Parsed features JSON from ARM data")
    parser.add_argument("--out", default="results.json", help="Output results file")
    args = parser.parse_args()

    x86_records = load_records([args.features_x86])
    arm_records = load_records([args.features_arm])

    print(f"Loaded {len(x86_records)} x86 records, {len(arm_records)} ARM records")
    print(f"x86 label dist: benign={sum(1 for r in x86_records if r['label']=='benign')}, "
          f"malicious={sum(1 for r in x86_records if r['label']=='malicious')}")
    print(f"ARM label dist: benign={sum(1 for r in arm_records if r['label']=='benign')}, "
          f"malicious={sum(1 for r in arm_records if r['label']=='malicious')}")

    results = []

    # Experiment A: Train x86 → Test x86 (baseline, cross-validation style)
    # Use first half for train, second half for test
    mid = len(x86_records) // 2
    results.append(run_experiment(
        "A: x86→x86 (baseline)",
        x86_records[:mid], x86_records[mid:],
        feature="frequency"
    ))

    # Experiment B: Train x86 → Test ARM (raw frequency features)
    results.append(run_experiment(
        "B: x86→ARM (raw features)",
        x86_records, arm_records,
        feature="frequency"
    ))

    # Experiment C: Train x86+ARM → Test ARM
    combined = x86_records + arm_records[:len(arm_records)//2]
    test_arm  = arm_records[len(arm_records)//2:]
    results.append(run_experiment(
        "C: x86+ARM→ARM (mixed training)",
        combined, test_arm,
        feature="frequency"
    ))

    # Experiment D: Train x86 → Test ARM (normalized category features)
    results.append(run_experiment(
        "D: x86→ARM (normalized categories)",
        x86_records, arm_records,
        feature="normalized"
    ))

    print(f"\n{'═'*60}")
    print("SUMMARY")
    print(f"{'Experiment':<35} {'Accuracy':>10} {'F1':>8}")
    print(f"{'─'*60}")
    for r in results:
        if "error" not in r:
            print(f"{r['experiment']:<35} {r['accuracy']:>9.1%} {r['f1']:>8.4f}")

    with open(args.out, "w") as f:
        json.dump(results, f, indent=2)
    print(f"\nFull results → {args.out}")


if __name__ == "__main__":
    main()
