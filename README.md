# ArchProbe

**Measuring cross-architecture stability of syscall behavioral signatures in containerized security environments.**

📄 **Paper (v2):** [Zenodo DOI 10.5281/zenodo.22701078](https://doi.org/10.5281/zenodo.22701078) — Published September 11, 2026 · Updated September 24, 2026

---

## Research Question

Syscall-based behavioral detection systems (IDS, container security monitors) are trained and deployed on x86. Real infrastructure spans x86 and ARM. This study asks:

> *Do containerized workloads produce architecture-invariant syscall behavioral signatures, and can a classifier trained on x86 traces detect threats on ARM with acceptable accuracy?*

## Motivation

Prof. Kang's 2024 *Optimus* system filters syscalls for container attack surface reduction — but like all existing syscall-based tools, it assumes a single target architecture. As ARM servers (AWS Graviton, Ampere Altra) and ARM edge devices become standard deployment targets, this assumption breaks silently.

ArchProbe quantifies that breakage, tests four feature representations (including Markov chain features), and uses bootstrap confidence intervals to honestly characterize what can and cannot be concluded at small data scales.

---

## Method

### Testbed

**FothOS** (Arch Linux security distribution) serves as the collection platform. Docker containers run on both `linux/amd64` (x86) and `linux/arm64` (ARM) using Docker Buildx with QEMU userspace emulation.

### Workloads

20 workloads: 10 benign, 10 malicious-pattern.

| Category | Examples |
|----------|---------|
| Benign | curl, wget, git, file I/O, DNS resolution, process fork |
| Malicious-pattern | port scan, process enum, credential harvest, C2 beacon, data exfil, log wipe |

All malicious workloads are **simulated** — contained inside isolated Docker containers with no real targets.

### Feature Representations

| Name | Description | Notes |
|------|-------------|-------|
| `frequency` | Relative frequency of each syscall name | Architecture-specific |
| `ngram2` | Bigram sequences of syscall names | Architecture-specific |
| `normalized` | 131 syscalls mapped to 8 semantic categories | Architecture-agnostic |
| `transition` | 9×9 first-order Markov matrix over categories | Architecture-agnostic + sequence-aware |

**Category map:** 131 syscall names → `file_io`, `network`, `process`, `memory`, `privilege`, `ipc`, `timing`, `sync` (+ `other`). Covers ARM-specific variants: `newfstatat` → `file_io`, `rt_sigaction`/`rt_sigprocmask` → `ipc`, etc.

### Experiments

| ID | Train | Test | Feature | Evaluation |
|----|-------|------|---------|------------|
| A | x86 | x86 | frequency | Leave-one-out CV |
| B | x86 | ARM | frequency | Bootstrap CI (n=200) |
| C | x86 + ARM (50%, stratified) | ARM (50%) | frequency | Single split |
| D | x86 | ARM | normalized | Bootstrap CI (n=200) |
| E | x86 | ARM | bigram | Bootstrap CI (n=200) |
| F | x86 | ARM | Markov transition | Bootstrap CI (n=200) |
| G | x86 | ARM (first-N syscalls) | normalized | N sweep |

---

## Repository Structure

```
archprobe/
├── collector/
│   ├── Dockerfile          # Ubuntu + strace collection image
│   ├── run_workload.sh     # 20 workload scripts
│   └── collect_all.sh      # Build image + run all workloads
├── data/
│   ├── x86/                # Raw .strace files (x86_64)
│   └── arm/                # Raw .strace files (aarch64)
├── analysis/
│   ├── parse_traces.py     # Strace → feature vectors (frequency, ngram2, normalized, transition)
│   ├── classify.py         # 7 experiments with LOO-CV and bootstrap CI
│   └── run_pipeline.sh     # End-to-end pipeline
└── results/
    ├── features_x86.json
    ├── features_arm.json
    └── results.json
```

---

## Reproducing the Results

### 1. Collect traces (requires Docker with buildx)

```bash
chmod +x collector/collect_all.sh
./collector/collect_all.sh x86   # x86 traces
./collector/collect_all.sh arm   # ARM traces (via QEMU or native)
```

### 2. Parse + classify

```bash
pip3 install scikit-learn numpy
chmod +x analysis/run_pipeline.sh
./analysis/run_pipeline.sh
```

Results appear in `results/results.json`.

---

## Results (v2 — with bootstrap CI and extended category map)

| Experiment | Acc (mean) | ± | F1 (mean) | ± | Notes |
|---|---|---|---|---|---|
| A: x86→x86 (LOO-CV) | 53.3% | 0.499 | 0.467 | 0.499 | Prior 100% was a lucky split |
| B: x86→ARM raw [boot] | 48.4% | 0.069 | 0.178 | 0.260 | All-benign predictor |
| C: x86+ARM→ARM (fixed) | 50.0% | — | 0.615 | — | Stratified split fixes v1 |
| D: x86→ARM normalized [boot] | 48.0% | 0.058 | 0.389 | 0.215 | Point: 55% (was 65% in v1) |
| E: x86→ARM bigram [boot] | 49.2% | 0.057 | 0.321 | 0.301 | Raw bigrams fail cross-arch |
| F: x86→ARM Markov [boot] | **53.4%** | 0.055 | 0.606 | 0.194 | Best cross-arch representation |
| G: early detection (best) | 50.0% | — | 0.000 | — | No signal at any N |

**Key findings:**
1. All cross-arch features fail (bootstrap means 48–53%, chance = 50%)
2. Even same-arch baseline is unreliable at N=15 (LOO-CV: 53.3% ± 49.9%)
3. Prior 65% normalized-feature result was partially an artifact of incomplete category mapping; corrected to 55%
4. Markov transition features are the strongest cross-arch representation; `file_io→ipc` is the most discriminative transition
5. Early detection shows no improvement with more observed syscalls — the mismatch is structural

**What the prior v1 paper got wrong:** The original Exp A (100%) used a single lucky 60/40 stratified split. LOO-CV reveals true within-arch performance is ~53%. Exp D (65%) was inflated by incomplete syscall mapping where ARM-specific syscalls accumulated in `other`, accidentally acting as an architecture detector rather than a behavior detector.

---

## Status

- [x] Workload suite (20 workloads)
- [x] Strace collection pipeline
- [x] Feature extraction (frequency, ngram2, normalized, **transition**)
- [x] Classification framework (**7 experiments**, LOO-CV, bootstrap CI)
- [x] Extended syscall category map (60 → **131 syscalls**)
- [x] x86 data (15 records) · ARM data (20 records)
- [x] Paper v2 published
- [ ] arXiv submission (needs cs.CR endorsement)
- [ ] Native ARM data collection (non-QEMU)
- [ ] Sequence models (HMM, 1D CNN) — requires larger dataset

---

## Author

Sherbekjon Rustamov — independent security researcher, Uzbekistan.
Applying to KAIST School of Computing, 2027.
Built on [FothOS](https://github.com/SherbekjonDev/FothOS).
