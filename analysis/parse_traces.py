"""
Parse raw strace output files into feature vectors.

Four representations:
  1. frequency   — {syscall: count} (bag-of-syscalls)
  2. ngram2      — consecutive syscall pairs as features
  3. normalized  — abstract semantic categories (architecture-agnostic)
  4. transition  — normalized category-to-category Markov transition matrix

Also stores first CAT_SEQ_CAP category labels as `cat_sequence` for
early-detection experiments.
"""

import re
import os
import json
import argparse
from collections import Counter, defaultdict
from pathlib import Path

CAT_SEQ_CAP = 5000  # max category-sequence length stored per trace

SYSCALL_CATEGORIES = {
    # ── File I/O ──────────────────────────────────────────────────────────────
    "open": "file_io",       "openat": "file_io",      "openat2": "file_io",
    "read": "file_io",       "write": "file_io",       "close": "file_io",
    "stat": "file_io",       "fstat": "file_io",       "lstat": "file_io",
    "statx": "file_io",      "newfstatat": "file_io",  # ARM stat variant
    "access": "file_io",     "faccessat": "file_io",   "faccessat2": "file_io",
    "unlink": "file_io",     "unlinkat": "file_io",
    "rename": "file_io",     "renameat": "file_io",    "renameat2": "file_io",
    "mkdir": "file_io",      "mkdirat": "file_io",
    "rmdir": "file_io",
    "chmod": "file_io",      "fchmod": "file_io",      "fchmodat": "file_io",
    "chown": "file_io",      "lchown": "file_io",      "fchown": "file_io",
    "fchownat": "file_io",
    "truncate": "file_io",   "ftruncate": "file_io",
    "lseek": "file_io",      "llseek": "file_io",
    "readlink": "file_io",   "readlinkat": "file_io",
    "symlink": "file_io",    "symlinkat": "file_io",
    "link": "file_io",       "linkat": "file_io",
    "creat": "file_io",
    "fcntl": "file_io",      # file-descriptor control
    "ioctl": "file_io",      # device/fd control
    "getdents64": "file_io", "getdents": "file_io",    # directory listing
    "getcwd": "file_io",
    "chdir": "file_io",      "fchdir": "file_io",
    "umask": "file_io",
    "statfs": "file_io",     "fstatfs": "file_io",
    "getxattr": "file_io",   "setxattr": "file_io",    "listxattr": "file_io",
    "removexattr": "file_io","lgetxattr": "file_io",   "fgetxattr": "file_io",
    "lsetxattr": "file_io",  "fsetxattr": "file_io",
    "llistxattr": "file_io", "flistxattr": "file_io",
    "lremovexattr": "file_io","fremovexattr": "file_io",
    "pread64": "file_io",    "pwrite64": "file_io",
    "readv": "file_io",      "writev": "file_io",
    "preadv": "file_io",     "pwritev": "file_io",
    "preadv2": "file_io",    "pwritev2": "file_io",
    "sendfile": "file_io",   "sendfile64": "file_io",
    "splice": "file_io",     "tee": "file_io",
    "copy_file_range": "file_io",
    "fallocate": "file_io",
    "fsync": "file_io",      "fdatasync": "file_io",
    "sync": "file_io",       "syncfs": "file_io",      "sync_file_range": "file_io",
    "inotify_init": "file_io","inotify_init1": "file_io",
    "inotify_add_watch": "ipc",  # epoll-family → ipc (below)
    "inotify_rm_watch": "file_io",
    "mkfifo": "file_io",     "mkfifoat": "file_io",
    "mknod": "file_io",      "mknodat": "file_io",
    "mount": "file_io",      "umount2": "file_io",
    "pivot_root": "file_io",
    "landlock_create_ruleset": "file_io",
    "landlock_add_rule": "file_io",
    "landlock_restrict_self": "file_io",

    # ── Network ───────────────────────────────────────────────────────────────
    "socket": "network",     "connect": "network",     "bind": "network",
    "listen": "network",     "accept": "network",      "accept4": "network",
    "send": "network",       "sendto": "network",      "sendmsg": "network",
    "sendmmsg": "network",
    "recv": "network",       "recvfrom": "network",    "recvmsg": "network",
    "recvmmsg": "network",
    "getsockopt": "network", "setsockopt": "network",
    "getpeername": "network","getsockname": "network",
    "shutdown": "network",
    "socketpair": "network",
    "socketcall": "network",

    # ── Process ───────────────────────────────────────────────────────────────
    "fork": "process",       "vfork": "process",
    "clone": "process",      "clone3": "process",
    "execve": "process",     "execveat": "process",
    "wait4": "process",      "waitpid": "process",     "waitid": "process",
    "wait3": "process",
    "exit": "process",       "exit_group": "process",
    "kill": "process",       "tkill": "process",       "tgkill": "process",
    "getpid": "process",     "gettid": "process",
    "getppid": "process",    "getpgid": "process",     "setpgid": "process",
    "setsid": "process",     "getsid": "process",
    "sched_yield": "process",
    "sched_getaffinity": "process",  "sched_setaffinity": "process",
    "sched_getparam": "process",     "sched_setparam": "process",
    "sched_getscheduler": "process", "sched_setscheduler": "process",
    "nice": "process",       "getpriority": "process", "setpriority": "process",
    "uname": "process",
    "personality": "process",
    "unshare": "process",
    "setns": "process",

    # ── Memory ────────────────────────────────────────────────────────────────
    "mmap": "memory",        "mmap2": "memory",        "munmap": "memory",
    "mprotect": "memory",    "brk": "memory",          "mremap": "memory",
    "madvise": "memory",     "mincore": "memory",
    "mlock": "memory",       "munlock": "memory",
    "mlock2": "memory",      "mlockall": "memory",     "munlockall": "memory",
    "msync": "memory",
    "memfd_create": "memory","membarrier": "memory",
    "userfaultfd": "memory",
    "process_vm_readv": "memory","process_vm_writev": "memory",
    "fadvise64": "memory",   # readahead hint for file pages

    # ── Privilege / security ──────────────────────────────────────────────────
    "setuid": "privilege",   "setgid": "privilege",
    "setreuid": "privilege", "setregid": "privilege",
    "setresuid": "privilege","setresgid": "privilege",
    "getuid": "privilege",   "getgid": "privilege",
    "geteuid": "privilege",  "getegid": "privilege",
    "getgroups": "privilege","setgroups": "privilege",
    "capset": "privilege",   "capget": "privilege",
    "prctl": "privilege",    "ptrace": "privilege",
    "setrlimit": "privilege","getrlimit": "privilege", "prlimit64": "privilege",
    "syslog": "privilege",   # kernel ring buffer — admin operation
    "chroot": "privilege",
    "seccomp": "privilege",
    "keyctl": "privilege",   "add_key": "privilege",   "request_key": "privilege",
    "swapon": "privilege",   "swapoff": "privilege",

    # ── IPC / event / fd-multiplexing ─────────────────────────────────────────
    "pipe": "ipc",           "pipe2": "ipc",
    "dup": "ipc",            "dup2": "ipc",            "dup3": "ipc",
    "eventfd": "ipc",        "eventfd2": "ipc",
    "signalfd": "ipc",       "signalfd4": "ipc",
    "epoll_create": "ipc",   "epoll_create1": "ipc",
    "epoll_ctl": "ipc",      "epoll_wait": "ipc",
    "epoll_pwait": "ipc",    "epoll_pwait2": "ipc",
    "select": "ipc",         "pselect6": "ipc",
    "poll": "ipc",           "ppoll": "ipc",
    "msgget": "ipc",         "msgsnd": "ipc",          "msgrcv": "ipc",
    "msgctl": "ipc",
    "semget": "ipc",         "semop": "ipc",           "semtimedop": "ipc",
    "semctl": "ipc",
    "shmget": "ipc",         "shmat": "ipc",           "shmdt": "ipc",
    "shmctl": "ipc",
    "mq_open": "ipc",        "mq_send": "ipc",         "mq_receive": "ipc",
    "mq_unlink": "ipc",
    "io_setup": "ipc",       "io_submit": "ipc",       "io_getevents": "ipc",
    "io_uring_enter": "ipc", "io_uring_setup": "ipc",  "io_uring_register": "ipc",

    # ── Timing ────────────────────────────────────────────────────────────────
    "nanosleep": "timing",   "clock_nanosleep": "timing",
    "alarm": "timing",
    "setitimer": "timing",   "getitimer": "timing",
    "timer_create": "timing","timer_settime": "timing","timer_gettime": "timing",
    "timer_delete": "timing",
    "timerfd_create": "timing","timerfd_settime": "timing","timerfd_gettime": "timing",
    "clock_gettime": "timing","clock_settime": "timing","clock_getres": "timing",
    "gettimeofday": "timing","settimeofday": "timing",
    "adjtimex": "timing",
    "times": "timing",

    # ── Sync / threading ─────────────────────────────────────────────────────
    "futex": "sync",
    "futex_wait": "sync",    "futex_wake": "sync",     "futex_waitv": "sync",
    "get_robust_list": "sync","set_robust_list": "sync",
    "set_tid_address": "sync",
    "rseq": "sync",
}

# Categories in a fixed, deterministic order for the transition matrix
CATEGORIES = ["file_io", "network", "process", "memory",
               "privilege", "ipc", "timing", "sync", "other"]
_CAT_IDX = {c: i for i, c in enumerate(CATEGORIES)}
_N_CATS = len(CATEGORIES)

SYSCALL_RE = re.compile(r'^(?:\[pid\s+\d+\]\s+|\d+\s+)?(\w+)\(')
_UNRESOLVED_RE = re.compile(r'^syscall_0x[0-9a-f]+$', re.IGNORECASE)


def parse_strace_file(path: str) -> list[str]:
    """Return ordered list of syscall names from a strace file."""
    syscalls = []
    with open(path, "r", errors="replace") as f:
        for line in f:
            m = SYSCALL_RE.match(line.strip())
            if m:
                name = m.group(1)
                if not _UNRESOLVED_RE.match(name):
                    syscalls.append(name)
    return syscalls


def frequency_vector(syscalls: list[str]) -> dict:
    return dict(Counter(syscalls))


def ngram_vector(syscalls: list[str], n: int = 2) -> dict:
    grams = zip(*[syscalls[i:] for i in range(n)])
    return dict(Counter("_".join(g) for g in grams))


def normalized_vector(syscalls: list[str]) -> dict:
    cats = [SYSCALL_CATEGORIES.get(s, "other") for s in syscalls]
    return dict(Counter(cats))


def transition_vector(syscalls: list[str]) -> dict:
    """
    First-order Markov transition matrix over syscall categories.

    Each entry key is "from_cat->to_cat".  Row values are normalized to
    sum to 1.0 (rows with zero observations stay 0.0).  Produces
    len(CATEGORIES)^2 = 81 features regardless of vocabulary size,
    making it fully architecture-agnostic.
    """
    cat_seq = [SYSCALL_CATEGORIES.get(s, "other") for s in syscalls]
    matrix = [[0] * _N_CATS for _ in range(_N_CATS)]

    for i in range(len(cat_seq) - 1):
        a = _CAT_IDX[cat_seq[i]]
        b = _CAT_IDX[cat_seq[i + 1]]
        matrix[a][b] += 1

    result = {}
    for i, cat_from in enumerate(CATEGORIES):
        row_sum = sum(matrix[i])
        for j, cat_to in enumerate(CATEGORIES):
            key = f"{cat_from}->{cat_to}"
            result[key] = matrix[i][j] / row_sum if row_sum > 0 else 0.0
    return result


def process_directory(data_dir: str, out_file: str):
    records = []
    for path in sorted(Path(data_dir).glob("*.strace")):
        stem = path.stem  # e.g. "benign_curl_x86_64"
        parts = stem.rsplit("_", 1)
        workload = parts[0] if len(parts) == 2 else stem
        arch = parts[1] if len(parts) == 2 else "unknown"
        label = "malicious" if workload.startswith("mal_") else "benign"

        syscalls = parse_strace_file(str(path))
        if not syscalls:
            print(f"  [warn] empty trace: {path.name}")
            continue

        cat_seq_full = [SYSCALL_CATEGORIES.get(s, "other") for s in syscalls]

        record = {
            "file": path.name,
            "workload": workload,
            "arch": arch,
            "label": label,
            "total_syscalls": len(syscalls),
            "frequency": frequency_vector(syscalls),
            "ngram2": ngram_vector(syscalls, 2),
            "normalized": normalized_vector(syscalls),
            "transition": transition_vector(syscalls),
            # Capped sequence for early-detection experiments
            "cat_sequence": cat_seq_full[:CAT_SEQ_CAP],
        }
        records.append(record)
        print(f"  {path.name}: {len(syscalls)} syscalls, label={label}")

    with open(out_file, "w") as f:
        json.dump(records, f, indent=2)
    print(f"\nSaved {len(records)} records → {out_file}")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Parse strace files into feature vectors")
    parser.add_argument("data_dir", help="Directory containing .strace files")
    parser.add_argument("out_file", help="Output JSON file")
    args = parser.parse_args()
    process_directory(args.data_dir, args.out_file)
