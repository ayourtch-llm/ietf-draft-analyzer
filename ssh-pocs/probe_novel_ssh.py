#!/usr/bin/env python3
"""
Test novel (no-CVE) SSH findings from ietf-draft-analyzer reports.

Finding: SSH authentication state flush failure when username changes
RFC 4252 Section 5: "The server implementation MUST carefully check them
in every message, and MUST flush any accumulated authentication states
if they change."

Test: After partial auth progress for user A, switch to user B mid-stream.
Check if the server properly resets state.

Usage: python probe_novel_ssh.py <host> <port> <user1> <pass1> <user2> <pass2>
"""

import paramiko
import socket
import sys
import time


def test_auth_state_flush(host, port, user1, pass1, user2, pass2):
    """
    Test whether the server properly flushes auth state when username changes.

    Strategy:
    1. Start keyboard-interactive or password auth for user1
    2. Before completing, switch to user2
    3. Check if user2's auth is influenced by user1's state

    Since OpenSSH doesn't support partial multi-method accumulation the
    way some other implementations do, we test a more subtle variant:
    - Auth as user1 with 'none' (get allowed methods)
    - Auth as user1 with wrong password (fail, but server allocates state)
    - Immediately auth as user2 with correct password
    - Check timing difference vs. direct auth for user2

    If the server doesn't flush state, the second auth might behave
    differently (wrong method list, timing difference, or even success
    with user1's credentials carrying over).
    """
    print("=" * 60)
    print("TEST: SSH Auth State Flush on Username Change (RFC 4252 §5)")
    print("=" * 60)

    # Baseline: direct auth for user2
    print("\n  Phase 1: Baseline — direct auth for user2")
    t0 = time.monotonic()
    ssh = paramiko.SSHClient()
    ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    try:
        ssh.connect(host, port=port, username=user2, password=pass2, timeout=10,
                    allow_agent=False, look_for_keys=False)
        baseline_ok = True
        baseline_time = time.monotonic() - t0
        print(f"  [OK] user2 auth succeeded in {baseline_time:.3f}s")
        # Get a command output to confirm identity
        _, stdout, _ = ssh.exec_command("whoami")
        whoami = stdout.read().decode().strip()
        print(f"  Identity confirmed: {whoami}")
        ssh.close()
    except Exception as e:
        print(f"  [FAIL] Baseline auth failed: {e}")
        return

    # Test: auth as user1 (wrong pass), then switch to user2
    print("\n  Phase 2: Auth user1 (fail), then switch to user2")
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(10)
    sock.connect((host, port))
    transport = paramiko.Transport(sock)
    transport.start_client()

    # Step 1: Try user1 with 'none' to get method list
    try:
        transport.auth_none(user1)
    except paramiko.BadAuthenticationType as e:
        methods1 = e.allowed_types
        print(f"  user1 allowed methods: {methods1}")
    except paramiko.SSHException:
        methods1 = []

    # Step 2: Try user1 with WRONG password
    try:
        transport.auth_password(user1, "WRONG_PASSWORD_DELIBERATE")
    except paramiko.AuthenticationException:
        print(f"  user1 auth failed (expected — wrong password)")
    except paramiko.SSHException as e:
        print(f"  user1 auth error: {e}")

    # Step 3: Now switch to user2 — server MUST flush user1's state
    print(f"  Switching to user2 (server should flush user1 state)...")

    # Check: does the server still offer the same methods for user2?
    try:
        transport.auth_none(user2)
    except paramiko.BadAuthenticationType as e:
        methods2 = e.allowed_types
        print(f"  user2 allowed methods: {methods2}")
    except paramiko.SSHException as e:
        print(f"  user2 method probe: {e}")
        methods2 = []

    # Step 4: Auth user2 with correct password
    t0 = time.monotonic()
    try:
        transport.auth_password(user2, pass2)
        switch_time = time.monotonic() - t0
        print(f"  [OK] user2 auth succeeded in {switch_time:.3f}s (after user1 fail)")

        # Confirm identity
        chan = transport.open_session()
        chan.exec_command("whoami")
        chan.settimeout(3)
        whoami = b""
        try:
            while True:
                chunk = chan.recv(1024)
                if not chunk:
                    break
                whoami += chunk
        except socket.timeout:
            pass
        whoami = whoami.decode().strip()
        print(f"  Identity confirmed: {whoami}")
        chan.close()

        if whoami == user2:
            print(f"  [OK] Server correctly authenticated as user2, not user1")
        elif whoami == user1:
            print(f"  [VULNERABLE!] Server authenticated as user1 despite switching!")
        else:
            print(f"  [?] Unexpected identity: {whoami}")

    except paramiko.AuthenticationException:
        switch_time = time.monotonic() - t0
        print(f"  [FAIL] user2 auth failed after user1 switch ({switch_time:.3f}s)")
        print(f"  This could mean the server disconnected or has a bug")
    except paramiko.SSHException as e:
        print(f"  [ERROR] {e}")

    transport.close()
    sock.close()

    # Phase 3: Rapid username switching
    print("\n  Phase 3: Rapid alternating username auth attempts")
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(10)
    sock.connect((host, port))
    transport = paramiko.Transport(sock)
    transport.start_client()

    attempts = [
        (user1, "wrong1"),
        (user2, "wrong2"),
        (user1, "wrong3"),
        (user2, pass2),  # This should succeed
    ]

    for i, (user, pw) in enumerate(attempts):
        try:
            transport.auth_password(user, pw)
            print(f"  Attempt {i+1} ({user}): SUCCESS")
            # Verify identity
            chan = transport.open_session()
            chan.exec_command("whoami")
            chan.settimeout(2)
            try:
                whoami = chan.recv(1024).decode().strip()
            except:
                whoami = "?"
            chan.close()
            print(f"  Identity: {whoami}")
            if whoami != user:
                print(f"  [VULNERABLE!] Authenticated as {whoami} but requested {user}!")
            break
        except paramiko.AuthenticationException:
            print(f"  Attempt {i+1} ({user}): FAILED (expected)")
        except paramiko.SSHException as e:
            print(f"  Attempt {i+1} ({user}): ERROR — {e}")
            break

    transport.close()
    sock.close()

    # Phase 4: Check MaxAuthTries behavior across username switches
    print("\n  Phase 4: Does username switching reset the attempt counter?")
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(10)
    sock.connect((host, port))
    transport = paramiko.Transport(sock)
    transport.start_client()

    success_count = 0
    fail_count = 0
    for i in range(20):
        user = user1 if i % 2 == 0 else user2
        try:
            transport.auth_password(user, "wrong_password")
        except paramiko.AuthenticationException:
            fail_count += 1
        except paramiko.SSHException as e:
            print(f"  Disconnected after {fail_count} failures: {e}")
            break

    print(f"  Managed {fail_count} failed auth attempts before disconnect")
    if fail_count > 6:
        print(f"  [NOTE] Username switching may be resetting the MaxAuthTries counter!")
        print(f"         (default MaxAuthTries=6, but we got {fail_count} attempts)")
    else:
        print(f"  [OK] Server enforced attempt limit correctly")

    try:
        transport.close()
    except:
        pass
    sock.close()
    print()


def main():
    if len(sys.argv) < 7:
        print(f"Usage: {sys.argv[0]} <host> <port> <user1> <pass1> <user2> <pass2>")
        print(f"Example: {sys.argv[0]} 192.168.0.129 22 test testpass root rootpass")
        sys.exit(1)

    host = sys.argv[1]
    port = int(sys.argv[2])
    user1 = sys.argv[3]
    pass1 = sys.argv[4]
    user2 = sys.argv[5]
    pass2 = sys.argv[6]

    test_auth_state_flush(host, port, user1, pass1, user2, pass2)


if __name__ == "__main__":
    main()
