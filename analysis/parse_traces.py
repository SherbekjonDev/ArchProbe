"""
Parse raw strace output files into feature vectors.

Three representations:
  1. frequency  — {syscall: count} dict (simple bag-of-syscalls)
  2. ngram       — bigram/trigram sequences as features
  3. normalized  — abstract categories instead of raw syscall names
"""

import re
import os
import json
import argparse
from collections import Counter, defaultdict
from pathlib import Path

# Maps raw syscall names to abstract categories.
# Architecture-specific variants map to the same category.
SYSCALL_CATEGORIES = {
    # File I/O
    "open": "file_io",    "openat": "file_io",   "openat2": "file_io",
    "read": "file_io",    "write": "file_io",    "close": "file_io",
    "stat": "file_io",    "fstat": "file_io",    "lstat": "file_io",
    "statx": "file_io",   "access": "file_io",   "faccessat": "file_io",
    "unlink": "file_io",  "unlinkat": "file_io", "rename": "file_io",
    "renameat": "file_io","mkdir": "file_io",    "mkdirat": "file_io",
    "chmod": "file_io",   "fchmod": "file_io",   "chown": "file_io",
    "truncate": "file_io","ftruncate": "file_io","lseek": "file_io",
    "readlink": "file_io","readlinkat": "file_io",
    # Network
    "socket": "network",  "connect": "network",  "bind": "network",
    "listen": "network",  "accept": "network",   "accept4": "network",
    "send": "network",    "sendto": "network",   "sendmsg": "network",
    "recv": "network",    "recvfrom": "network", "recvmsg": "network",
    "getsockopt": "network","setsockopt": "network","getpeername": "network",
    "getsockname": "network","shutdown": "network",
    # Process
    "fork": "process",    "vfork": "process",    "clone": "process",
    "clone3": "process",  "execve": "process",   "execveat": "process",
    "wait4": "process",   "waitpid": "process",  "waitid": "process",
    "exit": "process",    "exit_group": "process","kill": "process",
    "tkill": "process",   "tgkill": "process",   "getpid": "process",
    "getppid": "process", "getpgid": "process",  "setsid": "process",
    # Memory
    "mmap": "memory",     "mmap2": "memory",     "munmap": "memory",
    "mprotect": "memory", "brk": "memory",       "mremap": "memory",
    "madvise": "memory",  "mincore": "memory",
    # Privilege / security
    "setuid": "privilege","setgid": "privilege", "setreuid": "privilege",
    "setregid": "privilege","capset": "privilege","capget": "privilege",
    "prctl": "privilege", "ptrace": "privilege",
    # IPC
    "pipe": "ipc",        "pipe2": "ipc",        "dup": "ipc",
    "dup2": "ipc",        "dup3": "ipc",         "eventfd": "ipc",
    "signalfd": "ipc",    "epoll_create": "ipc", "epoll_ctl": "ipc",
    "epoll_wait": "ipc",  "select": "ipc",       "poll": "ipc",
    "ppoll": "ipc",       "inotify_add_watch": "ipc",
    # Time / misc
    "nanosleep": "timing","clock_nanosleep": "timing","alarm": "timing",
    "gettime": "timing",  "clock_gettime": "timing","gettimeofday": "timing",
    "futex": "sync",      "get_robust_list": "sync",
}

SYSCALL_RE = re.compile(r'^(?:\[pid\s+\d+\]\s+)?(\w+)\(')


def parse_strace_file(path: str) -> list[str]:
    """Return ordered list of syscall names from a strace file."""
    syscalls = []
    with open(path, "r", errors="replace") as f:
        for line in f:
            m = SYSCALL_RE.match(line.strip())
            if m:
                syscalls.append(m.group(1))
    return syscalls


def frequency_vector(syscalls: list[str]) -> dict:
    return dict(Counter(syscalls))


def ngram_vector(syscalls: list[str], n: int = 2) -> dict:
    grams = zip(*[syscalls[i:] for i in range(n)])
    return dict(Counter("_".join(g) for g in grams))


def normalized_vector(syscalls: list[str]) -> dict:
    cats = [SYSCALL_CATEGORIES.get(s, "other") for s in syscalls]
    return dict(Counter(cats))


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

        record = {
            "file": path.name,
            "workload": workload,
            "arch": arch,
            "label": label,
            "total_syscalls": len(syscalls),
            "frequency": frequency_vector(syscalls),
            "ngram2": ngram_vector(syscalls, 2),
            "normalized": normalized_vector(syscalls),
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
