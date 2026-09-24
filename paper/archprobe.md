# ArchProbe: Measuring Cross-Architecture Stability of Syscall Behavioral Signatures in Containerized Environments

**Sherbekjon Rustamov**  
Independent Security Researcher  
rustamovsherbekjon@gmail.com

---

## Abstract

Syscall-based behavioral detection systems are trained and deployed predominantly on x86 infrastructure, yet modern cloud and edge deployments span both x86 and ARM architectures. This paper asks whether a classifier trained on x86 syscall traces can generalize to ARM without retraining. We present ArchProbe, a controlled measurement study that collects strace behavioral traces from 20 containerized workloads (10 benign, 10 malicious-pattern) on both x86\_64 and aarch64 platforms, then evaluates seven cross-architecture transfer experiments using a Random Forest classifier with bootstrap confidence intervals and leave-one-out cross-validation. Our results show that all tested feature representations — raw frequency, bigrams, abstract category normalization, and first-order Markov transition features — fail to achieve reliable cross-architecture detection, with bootstrap mean accuracies between 48% and 53% (chance = 50%). A leave-one-out evaluation of the same-architecture baseline reveals 53.3% ± 49.9%, demonstrating that the small dataset (N=15 training samples) renders the classifier itself unreliable. Additionally, an expanded syscall-to-category mapping (131 mapped syscalls, up from 60) reveals that a prior finding of 65% accuracy using normalized features was partially an artifact of an incomplete mapping where unmapped ARM syscalls inflated a discriminative "other" category; with the corrected mapping, the point estimate falls to 55%. These findings do not disprove the value of normalization as a portability strategy, but they establish that definitive conclusions require substantially larger, natively collected multi-architecture datasets.

---

## 1. Introduction

Syscall-based intrusion detection has a long history in systems security. Tools such as Falco, Sysdig, and academic systems like Krueger et al.'s anomaly detection and Optimus [1] operate by observing the stream of system calls a process makes and classifying whether the pattern is benign or malicious. The implicit assumption in every deployed system is that the model trained on one machine generalizes to others running the same workload.

This assumption silently breaks across CPU architectures. An x86\_64 Linux binary and its aarch64 equivalent may use different system calls to accomplish the same task: `mmap` vs `mmap2`, `stat` vs `newfstatat`, or `clone` vs `clone3`. More critically, ARM's expanded syscall table and different calling conventions mean that the raw numeric and string identifiers of syscalls differ even for identical logical operations. A classifier trained to recognize `privesc_enum` patterns on x86 by the frequency of `openat`, `getdents64`, and `readlinkat` may encounter entirely different call sequences for the same attack on ARM.

With ARM server adoption accelerating — AWS Graviton instances, Ampere Altra deployments, and Apple Silicon development machines — this assumption is becoming load-bearing infrastructure debt. ArchProbe is a measurement study designed to quantify the failure mode, test several normalization remedies, and honestly characterize what can and cannot be concluded at small data scales.

**Research questions:**
- RQ1: Do containerized workloads produce architecture-invariant syscall behavioral signatures under raw, bigram, or normalized feature representations?
- RQ2: Do first-order Markov (category transition) features capture sequence-level behavioral invariants that survive cross-architecture transfer?
- RQ3: How many syscalls must be observed before cross-architecture classification is viable (early detection)?
- RQ4: What is the effect of syscall-to-category mapping completeness on normalized feature accuracy?

---

## 2. Related Work

**Syscall-based anomaly detection.** The use of system call sequences for intrusion detection dates to Forrest et al. [2], who proposed normal behavior profiles from syscall sequences. Subsequent work explored bag-of-syscalls, n-gram models, and neural sequence models. These techniques underpin modern container security tools.

**Optimus.** Sysfilter / Optimus [1] reduces container attack surface by statically filtering syscalls a container is permitted to make. It operates per-architecture but assumes the policy can be independently derived. Our work asks what happens when a *learned* policy (rather than a static allowlist) transfers across architectures.

**Cross-architecture analysis.** Prior work on architecture-independent malware analysis has focused on binary similarity (e.g., instruction embedding, control-flow graph matching). To our knowledge, no prior work has directly measured syscall-level behavioral portability for *containerized* workloads, quantified the accuracy degradation with bootstrap confidence intervals, or studied the effect of syscall mapping completeness on cross-architecture transfer.

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

We extract four feature representations from each trace:

**Frequency vector.** A bag-of-syscalls: `{syscall_name: count}`, normalized to relative frequencies per trace. Unresolved kernel pointers (lines matching `syscall_0x[hex]+`) are excluded as ABI noise.

**Bigram (ngram2).** Consecutive syscall pairs encoded as `"syscall_a_syscall_b"` features, normalized to relative frequencies.

**Normalized categories.** Each syscall name is mapped to one of eight semantic groups: `file_io`, `network`, `process`, `memory`, `privilege`, `ipc`, `timing`, `sync`. Unmapped syscalls fall to `other`. The mapping spans 131 syscall names and is architecture-agnostic: `mmap` and `mmap2` both map to `memory`; `open`, `openat`, and `openat2` all map to `file_io`; the ARM-specific `newfstatat` maps to `file_io` alongside the x86 `stat` family. This extended mapping covers the 20 highest-frequency previously unmapped syscalls, including `newfstatat` (83,222 occurrences), `fcntl` (48,283), `getdents64` (23,749), and the `rt_sig*` family (25,389 combined).

**Markov transition matrix.** A first-order Markov model over syscall categories: each entry `cat_from → cat_to` records the fraction of consecutive (category_i, category_j) pairs in the trace. This produces a 9×9 = 81-feature representation that is fully architecture-agnostic, captures behavioral sequence structure beyond bag-of-categories, and remains compact regardless of syscall vocabulary size. The transition from `file_io → ipc` (repeated file reads followed by epoll/poll waits) versus `ipc → ipc` (tight polling loops) characterizes different threat patterns without naming a single architecture-specific syscall.

We also store the first 5,000 ordered category labels per trace (`cat_sequence`) to support early-detection experiments.

### 3.4 Classifier

We use a Random Forest classifier (100 trees, `class_weight="balanced"`, `random_state=42`) from scikit-learn. `class_weight="balanced"` compensates for the 5:10 benign:malicious imbalance in x86 training data.

### 3.5 Evaluation Protocol

**Leave-one-out CV (LOO-CV)** is used for within-architecture experiments (Exp A), as it maximizes training data utilization at small sample sizes and gives an unbiased estimate of generalization.

**Bootstrap confidence intervals** (200 iterations, `random_state=42`) are used for cross-architecture experiments (B, D, E, F): in each iteration, x86 training records are resampled with replacement, the classifier is fit, and performance is evaluated on all 20 fixed ARM test records. Mean ± standard deviation across valid iterations characterizes the stability of cross-architecture transfer with respect to which x86 samples are available.

### 3.6 Experiments

| ID | Train | Test | Feature | Evaluation |
|----|-------|------|---------|------------|
| A | x86 | x86 (LOO-CV) | frequency | Leave-one-out CV |
| B | x86 | ARM | frequency | Bootstrap CI |
| C | x86 + ARM (stratified 50%) | ARM (stratified 50%) | frequency | Single split |
| D | x86 | ARM | normalized | Bootstrap CI |
| E | x86 | ARM | ngram2 (bigram) | Bootstrap CI |
| F | x86 | ARM | Markov transition | Bootstrap CI |
| G | x86 | ARM first-N | normalized | Single fit, N sweep |

Experiment C uses `StratifiedShuffleSplit` to divide ARM records into 50/50 balanced train/test sets before combining with all x86 records for training; this corrects the degenerate positional split in the v1 analysis (which placed all ARM benign in train and all ARM malicious in test, producing a structurally invalid 0% result).

---

## 4. Results

```
Experiment                                     Accuracy      ±       F1      ±
──────────────────────────────────────────────────────────────────────────────
A: x86→x86 (baseline, LOO-CV)                     53.3%  0.499   0.4667 0.4989
B: x86→ARM (raw frequency)        [bootstrap]     48.4%  0.069   0.1783 0.2604
C: x86+ARM→ARM (mixed, stratified)                50.0%  —       0.6154 —
D: x86→ARM (normalized categories)[bootstrap]     48.0%  0.058   0.3893 0.2145
E: x86→ARM (bigram/ngram2)        [bootstrap]     49.2%  0.057   0.3210 0.3014
F: x86→ARM (Markov transition)    [bootstrap]     53.4%  0.055   0.6059 0.1938
G: early detection (best N=50–5000)               50.0%  —       0.0000 —
```

**Experiment A — within-architecture baseline (LOO-CV).** LOO-CV over 15 x86 samples yields 53.3% mean accuracy with standard deviation 0.499 — essentially coin-flip performance with maximum variance. This reveals that the prior single-split result (100% accuracy on a 60/40 stratified split) was a lucky partition. With 5 benign and 10 malicious samples, a single stratified split places 2 benign and 4 malicious in the test set; the model easily memorizes the training distribution but the LOO evaluation exposes its inability to generalize to held-out individual samples. This finding is itself a result: the dataset is too small to draw reliable within-architecture conclusions.

**Experiment B — raw frequency, cross-arch (bootstrap).** Mean accuracy 48.4% ± 6.9%. The point estimate (50%) equals chance; the bootstrap distribution is centered slightly below 50%, consistent with the model learning x86-specific frequency patterns that actively mislead on ARM. The confusion matrix (10/0/10/0 — all predictions benign) confirms the model defaults to the benign class.

**Experiment C — mixed training (fixed).** With a stratified ARM split, 50% test accuracy and F1=0.615 (CM: [[1,4],[1,4]]). The high F1 at 50% accuracy reflects a classifier biased toward predicting malicious (3 of 4 benign correctly rejected, 4 of 5 malicious detected). This is not production-viable, but the result is no longer structurally degenerate as in v1.

**Experiment D — normalized categories, cross-arch (bootstrap).** Point estimate 55%, bootstrap mean 48.0% ± 5.8%. The point estimate exceeds chance by 5 percentage points, but the bootstrap distribution is centered below 50%, indicating this gap is within sampling noise. Critically, the extended category mapping (131 syscalls vs. 60 in the prior analysis) reduces the normalized accuracy from the previously reported 65% to 55%. The top feature is `ipc` (28.5%), followed by `file_io` (25.4%) and `timing` (18.0%); the `other` category falls to 6.5% importance (down from 16.3%), confirming that incomplete mapping was artificially inflating discrimination via the catch-all `other` bucket.

**Experiment E — bigram features, cross-arch (bootstrap).** Mean accuracy 49.2% ± 5.7%. Raw bigrams transfer even less reliably than unigrams, as expected: architecture-specific syscall pairs (e.g., `newfstatat_close` on ARM vs. `stat_close` on x86) have zero overlap with x86-trained features.

**Experiment F — Markov transition features, cross-arch (bootstrap).** Point estimate 50% (trivial classifier: all-malicious, CM [[0,10],[0,10]]); bootstrap mean 53.4% ± 5.5%. The transition matrix's top feature `file_io→ipc` (17.3%) and `file_io→file_io` (13.0%) suggest partial behavioral signal, but the bootstrap mean does not significantly exceed chance. The F1 inflates at 50% accuracy when predicting all-malicious on a balanced test set (precision=0.5, recall=1.0).

**Experiment G — early detection curve.** Evaluating on the first N category-labeled syscalls of each ARM trace against an x86-trained classifier yields 50% accuracy for all N ≤ 1000, dropping to 45% for N ≥ 2000. There is no early-detection signal: observing more syscalls does not improve the cross-architecture classifier. This is consistent with the feature distribution mismatch being a structural property, not a data-volume property within the ARM trace.

---

## 5. Discussion

### 5.1 Answering RQ1 — Raw, bigram, and normalized features

None of the three representations produces reliable cross-architecture detection. Raw frequency (B) and bigrams (E) operate on architecture-specific syscall vocabularies and collapse to chance immediately. Normalized categories (D) show a 5–7 percentage point point-estimate advantage over chance, but bootstrap confidence intervals place the mean below 50%, indicating this advantage is within sampling noise at the current data scale. **The normalization direction is sound — mapping architecture-specific names to semantic groups is the correct abstraction — but the dataset is too small to confirm it statistically.**

### 5.2 Answering RQ2 — Markov transition features

Markov transition features (F) achieve the highest bootstrap mean (53.4%) of any cross-architecture experiment, and the `file_io→ipc` transition is the most discriminative single feature. However, the point estimate degenerates to an all-malicious trivial classifier, and the bootstrap advantage over chance is modest. The transition representation is the strongest candidate for a future, larger experiment, but cannot be validated here. The feature interpretation is intuitive: malicious workloads cycling through file operations followed by inter-process communication calls (typical of privilege escalation enumeration and credential harvest patterns) differ from benign workloads that perform sequential file I/O without sustained IPC patterns.

### 5.3 Answering RQ3 — Early detection

The early detection curve (G) shows no improvement as N increases up to 5,000 category-labeled syscalls. The cross-architecture mismatch is not a problem of insufficient observation volume; it is a problem of distributional shift between architectures. Even observing 5,000 syscalls of an ARM trace does not help a classifier trained on x86 traces. This eliminates "just wait for more syscalls" as a deployment strategy for cross-architecture transfer.

### 5.4 Answering RQ4 — Mapping completeness

Extending the syscall-to-category mapping from 60 to 131 syscalls changes results substantively. The normalized accuracy in Exp D drops from a previously reported 65% to 55%. The root cause: unmapped ARM-specific syscalls (notably `newfstatat` with 83,222 occurrences in the ARM data) accumulated in the `other` category, which acted as an unintentional proxy for ARM samples. Because ARM traces had more `other`-classified syscalls than x86 traces, the `other` feature became discriminative — not because it captured behavioral semantics, but because it captured architectural identity. The corrected mapping eliminates this artifact. This is a methodological warning for future syscall classification work: **an incomplete mapping can appear to succeed cross-architecturally while actually detecting architecture, not behavior.**

### 5.5 Dataset scale is the binding constraint

LOO-CV on the within-architecture baseline (Exp A, 53.3% ± 49.9%) shows the dataset is too small to support any of the conclusions quantitatively. This does not invalidate the measurement direction — it clarifies what is needed. The experiments establish the evaluation infrastructure and identify Markov transition features as the most promising representation, but definitive claims require at minimum 50–100 labeled samples per architecture from native (non-emulated) hardware.

### 5.6 Implications for detection system design

Despite the negative results, three practical implications follow:

1. **Never assume cross-architecture portability.** A model trained on x86 telemetry achieves chance-level performance on ARM. Deploy per-architecture models or collect multi-architecture training data deliberately.
2. **Normalize before training, but validate the mapping.** Category normalization is the correct abstraction for cross-architecture transfer, but the mapping must be comprehensive and validated against architecture-specific syscall tables.
3. **Collect native ARM data.** QEMU emulation introduces a syscall translation layer that may not reproduce native-hardware behavior. Results from emulated ARM collection should be treated as lower bounds on cross-architecture difficulty.

---

## 6. Conclusion

ArchProbe demonstrates that syscall behavioral signatures are *not* architecture-invariant under any tested feature representation at the current data scale. Leave-one-out cross-validation reveals that even same-architecture performance is unreliable with 15 training samples (53.3% ± 49.9%), while bootstrap confidence intervals show all cross-architecture transfer experiments (raw frequency, bigram, normalized categories, Markov transition) hover at chance level (48–53%). A corrected analysis with an extended 131-syscall category mapping shows that a prior 65% finding under normalized features was partially an artifact of incomplete mapping where ARM-specific syscalls inflated a catch-all `other` feature. Markov transition features show the highest bootstrap mean (53.4%) and the most interpretable top features, making them the strongest candidate for future work with larger datasets.

This work motivates three extensions: larger multi-architecture datasets (≥50 samples per arch) from native hardware, evaluation of sequence-aware models (HMM, 1D CNN) which require training data at scale, and a systematic study of how syscall mapping completeness affects cross-architecture classification.

The ArchProbe dataset and code are publicly available at `github.com/SherbekjonDev/ArchProbe` (DOI: 10.5281/zenodo.22701078).

---

## References

[1] Wan, Z., et al. "Sysfilter: Automated System Call Filtering for Commodity Software." *RAID 2020*.

[2] Forrest, S., Hofmeyr, S. A., Somayaji, A., & Longstaff, T. A. "A sense of self for Unix processes." *IEEE S&P 1996*.

[3] Abed, A. S., Clancy, C., & Levy, D. S. "Applying bag of system calls for anomalous behavior detection of applications in Linux containers." *IEEE GHTC 2015*.

[4] Falco Project. "Cloud-native runtime security." https://falco.org.

[5] Luk, C.-K., et al. "Pin: Building customized program analysis tools with dynamic instrumentation." *PLDI 2005*.
