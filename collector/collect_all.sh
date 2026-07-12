#!/bin/bash
# Run all workloads inside a Docker container and collect strace output.
# Usage: ./collect_all.sh [x86|arm]
#
# Requires: Docker with buildx + linux/amd64 and linux/arm64 support

set -e

ARCH=${1:-"x86"}
DATA_DIR="$(dirname "$0")/../data/$ARCH"
mkdir -p "$DATA_DIR"

PLATFORM="linux/amd64"
[[ "$ARCH" == "arm" ]] && PLATFORM="linux/arm64"

IMAGE="archprobe-collector:$ARCH"

WORKLOADS=(
  benign_curl benign_wget benign_git benign_python
  benign_file_io benign_dns benign_fork benign_ssh_keygen
  benign_find benign_proc_enum
  mal_recon_net mal_recon_proc mal_file_staging mal_cred_harvest
  mal_persistence mal_c2_beacon mal_exfil mal_privesc_enum
  mal_log_wipe mal_reverse_shell_sim
)

echo "=== ArchProbe: building collector image for $PLATFORM ==="
docker buildx build \
  --platform "$PLATFORM" \
  --load \
  -t "$IMAGE" \
  "$(dirname "$0")"

echo ""
echo "=== Collecting traces ($ARCH / $PLATFORM) ==="
PASS=0
FAIL=0

for WL in "${WORKLOADS[@]}"; do
  echo -n "  [$WL] ... "
  if docker run --rm \
      --platform "$PLATFORM" \
      --cap-add SYS_PTRACE \
      --security-opt seccomp=unconfined \
      --network bridge \
      -v "$(realpath "$DATA_DIR"):/data" \
      "$IMAGE" "$WL" "/data" > /tmp/archprobe_run.log 2>&1; then
    echo "ok"
    PASS=$((PASS+1))
  else
    echo "FAILED (see /tmp/archprobe_run.log)"
    FAIL=$((FAIL+1))
  fi
done

echo ""
echo "=== Done: $PASS ok, $FAIL failed ==="
echo "=== Traces in: $DATA_DIR ==="
ls -lh "$DATA_DIR"/*.strace 2>/dev/null | awk '{print $5, $9}'
