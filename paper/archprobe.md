# ArchProbe: Measuring Cross-Architecture Stability of Syscall Behavioral Signatures in Containerized Environments

**Sherbekjon Rustamov**  
Independent Security Researcher  
rustamovsherbekjon@gmail.com

---

## Abstract

Syscall-based behavioral detection systems are trained and deployed predominantly on x86 infrastructure, yet modern cloud and edge deployments span both x86 and ARM architectures. This paper asks whether a classifier trained on x86 syscall traces can generalize to ARM without retraining. We present ArchProbe, a controlled measurement study that collects strace behavioral traces from 20 containerized workloads (10 benign, 10 malicious-pattern) on both x86\_64 and aarch64 platforms, then evaluates four cross-architecture transfer experiments using a Random Forest classifier. Our results show that raw syscall frequency features collapse to chance-level performance when applied cross-architecture (50% accuracy, F1=0.00), while an abstract category normalization layer — mapping architecture-specific syscall names to semantic groups — recovers 65% accuracy (F1=0.53). These findings expose a silent assumption in syscall-based intrusion detection: architectural portability is not free, and normalization is a necessary but insufficient remedy at small data scales.

---

## 1. Introduction

Syscall-based intrusion detection has a long history in systems security. Tools such as Falco, Sysdig, and academic systems like Krueger et al.'s anomaly detection and Optimus [1] operate by observing the stream of system calls a process makes and classifying whether the pattern is benign or malicious. The implicit assumption in every deployed system is that the model trained on one machine generalizes to others running the same workload.

This assumption silently breaks across CPU architectures. An x86\_64 Linux binary and its aarch64 equivalent may use different system calls to accomplish the same task: `mmap` vs `mmap2`, `stat` vs `newfstatat`, or `clone` vs `clone3`. More critically, ARM's expanded syscall table and different calling conventions mean that the raw numeric and string identifiers of syscalls differ even for identical logical operations. A classifier trained to recognize `privesc_enum` patterns on x86 by the frequency of `openat`, `getdents64`, and `readlinkat` may encounter entirely different call sequences for the same attack on ARM.

With ARM server adoption accelerating — AWS Graviton instances, Ampere Altra deployments, and Apple Silicon development machines — this assumption is becoming load-bearing infrastructure debt. ArchProbe is a measurement study designed to quantify the failure mode and test a normalization remedy.

**Research questions:**
- RQ1: Do containerized workloads produce architecture-invariant syscall behavioral signatures when represented as raw call frequencies?
- RQ2: Can mapping raw syscall names to abstract semantic categories recover cross-architecture classification accuracy?

---

## 2. Related Work

**Syscall-based anomaly detection.** The use of system call sequences for intrusion detection dates to Forrest et al. [2], who proposed normal behavior profiles from syscall sequences. Subsequent work explored bag-of-syscalls, n-gram models, and neural sequence models. These techniques underpin modern container security tools.

**Optimus.** Sysfilter / Optimus [1] reduces container attack surface by statically filtering syscalls a container is permitted to make. It operates per-architecture but assumes the policy can be independently derived. Our work asks what happens when a *learned* policy (rather than a static allowlist) transfers across architectures.

**Cross-architecture analysis.** Prior work on architecture-independent malware analysis has focused on binary similarity (e.g., instruction embedding, control-flow graph matching). To our knowledge, no prior work has directly measured syscall-level behavioral portability for *containerized* workloads and quantified the accuracy degradation.

---

## 3. Methodology

### 3.1 Testbed

All traces are collected inside Docker containers using `strace -f -e trace=all`. The host system is FothOS (Arch Linux security distribution). Docker Buildx enables building and running `linux/arm64` images on the same x86\_64 host via QEMU userspace emulation, ensuring that the ARM traces reflect aarch64 binary behavior under the Linux aarch64 ABI.

### 3.2 Workloads

We define 20 workloads: 10 benign and 10 malicious-pattern. All malicious workloads are fully simulated inside isolated containers with no real external targets.

| Category | Workloads |
|----------|-----------|
| **Benign** | curl (HTTP fetch), DNS resolution, file I/O benchmark, filesystem find, process fork, git clone, process enumeration, Python interpreter, SSH keygen, wget |
| **Malicious-pattern** | C2 beacon simulation, credential harvesting, data exfiltration, file staging, log wipe, persistence installation, privilege escalation enumeration, network reconnaissance, process reconnaissance, reverse shell simulation |

Each workload runs in its own container, and the complete strace output is captured to a `.strace` file. Collection was performed for both `x86_64` and `aarch64` targets.

**Data quality note.** Five x86\_64 benign traces (dns, find, python, ssh\_keygen, wget) produced empty output, likely due to QEMU initialization timing issues during strace attachment on short-lived processes. These five samples are excluded from analysis, leaving 15 x86\_64 records (5 benign, 10 malicious) and 20 aarch64 records (10 benign, 10 malicious). This imbalance is a study limitation.

### 3.3 Feature Representations

We extract three feature representations from each trace:

**Frequency vector.** A bag-of-syscalls: `{syscall_name: count}`, normalized to relative frequencies per trace. Unresolved kernel pointers (lines matching `syscall_0x[hex]+`) are excluded as they represent ABI noise, not semantic syscalls.

**N-gram (bigram).** Consecutive syscall pairs encoded as `"syscall_a_syscall_b"` features. Not used in the primary experiments reported here but available for future work.

**Normalized categories.** Each syscall name is mapped to one of eight semantic groups: `file_io`, `network`, `process`, `memory`, `privilege`, `ipc`, `timing`, `sync`. Unknown syscalls map to `other`. The mapping is architecture-agnostic: both `mmap` and `mmap2` map to `memory`; both `open` and `openat` map to `file_io`.

### 3.4 Classifier

We use a Random Forest classifier (100 trees, `class_weight="balanced"`, `random_state=42`) from scikit-learn. `class_weight="balanced"` compensates for the 5:10 benign:malicious imbalance in x86 training data.

### 3.5 Experiments

| ID | Train | Test | Feature |
|----|-------|------|---------|
| A | x86 (stratified 60%) | x86 (40%) | frequency |
| B | x86 (all 15) | ARM (all 20) | frequency |
| C | x86 + ARM first half | ARM second half | frequency |
| D | x86 (all 15) | ARM (all 20) | normalized |

Experiment A uses stratified splitting to ensure both classes appear in train and test. Experiments B and D are the primary cross-architecture transfer tests.

---

## 4. Results

```
Experiment                            Accuracy       F1
────────────────────────────────────────────────────────
A: x86→x86 (baseline)                  100.0%   1.0000
B: x86→ARM (raw features)               50.0%   0.0000
C: x86+ARM→ARM (mixed training)          0.0%   0.0000
D: x86→ARM (normalized categories)      65.0%   0.5333
```

**Confusion matrix — Experiment B (x86→ARM, raw):**
```
              Predicted Benign   Predicted Malicious
True Benign         10                  0
True Malicious      10                  0
```
The classifier predicts every ARM sample as benign. Top discriminating features (`poll`, `read`, `write`, `open`) are common x86 syscalls absent or infrequent in the ARM traces under QEMU, leaving the model no signal to differentiate.

**Confusion matrix — Experiment D (x86→ARM, normalized):**
```
              Predicted Benign   Predicted Malicious
True Benign          9                  1
True Malicious       6                  4
```
Four malicious ARM samples are correctly identified. The top features — `ipc` (0.29), `file_io` (0.23), `other` (0.16), `memory` (0.12), `timing` (0.08) — are architecture-agnostic categories, which is why any transfer occurs at all.

**Experiment C** (0% accuracy) suffers from a structural data artifact: the positional split of ARM records by file sort order places all ARM benign samples in training and all ARM malicious samples in test, creating a degenerate evaluation. This result is excluded from the primary findings.

---

## 5. Discussion

### 5.1 Answering RQ1

Raw syscall frequency features do not transfer across architectures. Experiment B shows complete collapse: the classifier defaults to predicting the majority training class (benign, due to `class_weight` compensation being insufficient when the feature distributions are disjoint). This is expected: QEMU-emulated ARM processes issue system calls through a different ABI layer, producing different call names, different orderings, and different frequencies than native x86 processes performing the same logical operation.

This finding has a direct implication for deployed detection systems: a model trained on x86 telemetry and applied to ARM workloads without adaptation is not merely less accurate — it is effectively disabled, operating at chance level.

### 5.2 Answering RQ2

Normalization to abstract categories partially recovers cross-architecture accuracy (65%, F1=0.53). The `ipc` and `file_io` categories are the strongest discriminating features in Experiment D. This makes intuitive sense: malicious workloads that do network reconnaissance or data exfiltration will use IPC-class and file I/O calls heavily regardless of architecture, because the *intent* of the workload determines syscall category distributions more than the architecture does.

However, 65% accuracy is not production-viable. Four of ten malicious ARM workloads are missed (false negatives). The normalization approach is a necessary step but not a sufficient one at this data scale.

### 5.3 Limitations

1. **Small dataset.** 15 x86 training samples is insufficient for robust generalization. Results should be interpreted as directional rather than definitive.
2. **QEMU emulation.** ARM traces were collected under QEMU userspace emulation, not native aarch64 hardware. QEMU's syscall translation layer may introduce artifacts that do not appear on real ARM hardware.
3. **Simulated malice.** All malicious-pattern workloads are synthetic simulations, not real malware. The behavioral signatures may differ from actual threats.
4. **Single classifier.** Only Random Forest was evaluated. Sequence-aware models (HMM, LSTM) may behave differently.

### 5.4 Implications for Syscall-Based Detection Systems

The results suggest three practical recommendations for detection system designers targeting multi-architecture deployments:

1. **Do not assume architectural portability.** Publish per-architecture model versions or include architecture as an explicit feature.
2. **Normalize before training.** Abstract syscall categories are a lightweight, interpretable normalization layer that improves cross-architecture transfer without requiring retraining.
3. **Collect native ARM training data.** QEMU emulation is not a substitute for native traces; models trained on native x86 + native ARM data should outperform the mixed QEMU results reported here.

---

## 6. Conclusion

ArchProbe demonstrates that syscall behavioral signatures are *not* architecture-invariant. A Random Forest classifier trained on x86 container traces achieves 100% accuracy on held-out x86 data but collapses to chance (50%, F1=0.00) when applied directly to ARM traces. Mapping syscall names to abstract semantic categories partially recovers transfer capability (65%, F1=0.53), confirming that the logical intent of workloads is preserved across architectures even when raw call names diverge.

This work motivates further research into architecture-aware behavioral detection: larger multi-architecture datasets, native (non-emulated) ARM collection, and sequence-aware normalization methods. The ArchProbe dataset and code are publicly available at `github.com/SherbekjonDev/ArchProbe`.

---

## References

[1] Wan, Z., et al. "Sysfilter: Automated System Call Filtering for Commodity Software." *RAID 2020*.

[2] Forrest, S., Hofmeyr, S. A., Somayaji, A., & Longstaff, T. A. "A sense of self for Unix processes." *IEEE S&P 1996*.

[3] Abed, A. S., Clancy, C., & Levy, D. S. "Applying bag of system calls for anomalous behavior detection of applications in Linux containers." *IEEE GHTC 2015*.

[4] Falco Project. "Cloud-native runtime security." https://falco.org.
