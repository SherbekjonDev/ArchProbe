# ArchProbe

**Measuring cross-architecture stability of syscall behavioral signatures in containerized security environments.**

---

## Research Question

Syscall-based behavioral detection systems (IDS, container security monitors) are trained and deployed on x86. Real infrastructure spans x86 and ARM. This study asks:

> *Do containerized workloads produce architecture-invariant syscall behavioral signatures, and can a classifier trained on x86 traces detect threats on ARM with acceptable accuracy?*

## Motivation

Prof. Kang's 2024 *Optimus* system filters syscalls for container attack surface reduction — but like all existing syscall-based tools, it assumes a single target architecture. As ARM servers (AWS Graviton, Ampere Altra) and ARM edge devices become standard deployment targets, this assumption breaks silently.

ArchProbe quantifies that breakage and tests whether a normalization layer can recover it.

---

## Method

### Testbed

**FothOS** (Arch Linux security distro) serves as the collection platform. Docker containers run on both `linux/amd64` (x86) and `linux/arm64` (ARM) using Docker Buildx.

### Workloads

20 workloads: 10 benign, 10 malicious-pattern.

| Category | Examples |
|----------|---------|
| Benign | curl, wget, git, file I/O, DNS resolution, process fork |
| Malicious-pattern | port scan, process enum, credential harvest, C2 beacon, data exfil, log wipe |

All malicious workloads are **simulated** — contained inside isolated Docker containers with no real targets.

### Syscall Collection

```bash
strace -f -e trace=all -o output.strace <workload>
```

Captures full syscall traces including forked children (`-f`).

### Feature Representations

| Name | Description |
|------|-------------|
| `frequency` | Relative frequency of each syscall name |
| `ngram2` | Bigram sequences of syscall names |
| `normalized` | Mapped to 8 abstract categories (file\_io, network, process, memory, privilege, ipc, timing, sync) |

### Experiments

| Experiment | Train | Test | Feature |
|-----------|-------|------|---------|
| A | x86 | x86 | frequency (baseline) |
| B | x86 | ARM | frequency (cross-arch) |
| C | x86+ARM | ARM | frequency (mixed) |
| D | x86 | ARM | normalized (cross-arch + abstraction) |

**Classifier:** Random Forest (100 trees). Metrics: accuracy, F1, confusion matrix.

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
│   ├── parse_traces.py     # Strace → feature vectors (JSON)
│   ├── classify.py         # 4 classification experiments
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
# x86
chmod +x collector/collect_all.sh
./collector/collect_all.sh x86

# ARM (on ARM host, or Docker with QEMU emulation)
./collector/collect_all.sh arm
```

### 2. Parse + classify

```bash
pip3 install scikit-learn numpy
chmod +x analysis/run_pipeline.sh
./analysis/run_pipeline.sh
```

Results appear in `results/results.json`.

---

## Status

- [x] Workload suite (20 workloads)
- [x] Strace collection pipeline
- [x] Feature extraction (frequency, n-gram, normalized)
- [x] Classification framework (4 experiments)
- [ ] x86 data collected
- [ ] ARM data collected
- [ ] Results

---

## Author

Sherbekjon Rustamov — independent security researcher, Uzbekistan.
Applying to KAIST School of Computing, 2027.
Built on [FothOS](https://github.com/SherbekjonDev/FothOS).
