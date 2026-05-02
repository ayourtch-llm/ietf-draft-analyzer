#!/usr/bin/env python3
"""
Post-authentication SSH security tests.
Tests findings from rfc-analyzer that require valid credentials.

Tests:
  1. Direct-tcpip originator spoofing (RFC 4254 Section 7.2)
  2. X11 channel open without prior forwarding request (RFC 4254 Section 6.3.2)
  3. TCP forwarding to localhost/internal services
  4. Channel type fuzzing — open unusual channel types
  5. Environment variable injection
  6. Multiple concurrent channels / resource exhaustion

Usage: python probe_post_auth.py <host> <port> <username> <password>
"""

import paramiko
import socket
import sys
import time
import threading


def get_transport(host, port, username, password):
    """Create an authenticated paramiko transport."""
    ssh = paramiko.SSHClient()
    ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    ssh.connect(host, port=port, username=username, password=password, timeout=10)
    return ssh, ssh.get_transport()


# ---------------------------------------------------------------------------
# Test 1: Direct-tcpip originator spoofing
# ---------------------------------------------------------------------------

def test_direct_tcpip_spoofing(host, port, username, password):
    """
    RFC 4254 Section 7.2: The originator IP/port in direct-tcpip channel
    requests is informational only. Test if the server allows tunneling
    to internal services and whether it validates originator fields.

    This tests:
    - Can we open a tunnel to 127.0.0.1 on the server? (SSRF-like)
    - Does the server accept arbitrary originator IPs?
    - Can we reach services only bound to localhost?
    """
    print("=" * 60)
    print("TEST 1: Direct-tcpip Originator Spoofing (RFC 4254 §7.2)")
    print("=" * 60)

    ssh, transport = get_transport(host, port, username, password)

    targets = [
        # (dest_host, dest_port, description)
        ("127.0.0.1", 22, "SSH on localhost (loopback)"),
        ("127.0.0.1", 80, "HTTP on localhost"),
        ("127.0.0.1", 25, "SMTP on localhost"),
        ("127.0.0.1", 3306, "MySQL on localhost"),
        ("127.0.0.1", 5432, "PostgreSQL on localhost"),
        ("127.0.0.1", 6379, "Redis on localhost"),
        ("10.0.0.1", 22, "Internal network 10.0.0.1:22"),
        ("192.168.1.1", 80, "Gateway 192.168.1.1:80"),
    ]

    # Spoofed originator addresses to test
    originators = [
        ("127.0.0.1", 12345, "loopback spoof"),
        ("192.0.2.100", 54321, "RFC 5737 TEST-NET spoof"),
        ("0.0.0.0", 0, "zero address"),
    ]

    print("\n  Part A: Can we tunnel to internal services?")
    accessible = []
    for dest_host, dest_port, desc in targets:
        try:
            chan = transport.open_channel(
                "direct-tcpip",
                (dest_host, dest_port),
                ("192.168.0.1", 22222)  # normal-looking originator
            )
            if chan:
                # Try to read a banner if the service sends one
                chan.settimeout(2)
                banner = b""
                try:
                    banner = chan.recv(1024)
                except socket.timeout:
                    pass
                banner_str = banner.decode("utf-8", errors="replace").strip()[:80]
                accessible.append((dest_host, dest_port, desc, banner_str))
                print(f"  [OPEN] {desc} — channel opened! Banner: {banner_str or '(none)'}")
                chan.close()
            else:
                print(f"  [CLOSED] {desc} — channel returned None")
        except paramiko.ChannelException as e:
            code, msg = e.args
            print(f"  [DENIED] {desc} — code={code} msg={msg}")
        except Exception as e:
            print(f"  [ERROR] {desc} — {e}")

    if accessible:
        print(f"\n  [FINDING] {len(accessible)} internal service(s) accessible via SSH tunnel!")
        print("           Authenticated users can reach localhost-bound services")
        # Check if SSH on loopback is accessible (common SSRF vector)
        ssh_tunnel = [a for a in accessible if a[1] == 22 and a[0] == "127.0.0.1"]
        if ssh_tunnel:
            print("  [NOTE] SSH itself is tunnelable — could be used for lateral movement")
    else:
        print("\n  [OK] No internal services accessible (TCP forwarding may be disabled)")

    print("\n  Part B: Does the server validate originator IP fields?")
    # Try the same tunnel but with different spoofed originators
    for orig_ip, orig_port, desc in originators:
        try:
            chan = transport.open_channel(
                "direct-tcpip",
                ("127.0.0.1", 22),  # target: SSH on loopback
                (orig_ip, orig_port)
            )
            if chan:
                chan.settimeout(1)
                try:
                    banner = chan.recv(256)
                except:
                    banner = b""
                print(f"  [ACCEPTED] Originator {orig_ip}:{orig_port} ({desc}) — server didn't validate!")
                chan.close()
            else:
                print(f"  [REJECTED] Originator {orig_ip}:{orig_port} ({desc})")
        except paramiko.ChannelException as e:
            print(f"  [DENIED] Originator {orig_ip}:{orig_port} ({desc}) — {e.args}")
        except Exception as e:
            print(f"  [ERROR] Originator {orig_ip}:{orig_port} ({desc}) — {e}")

    ssh.close()
    print()


# ---------------------------------------------------------------------------
# Test 2: X11 channel without forwarding request
# ---------------------------------------------------------------------------

def test_x11_unrequested(host, port, username, password):
    """
    RFC 4254 Section 6.3.2: Implementations MUST reject X11 channel open
    requests if they have not requested X11 forwarding.

    We authenticate, do NOT request X11 forwarding, then try to open
    an X11 channel directly.
    """
    print("=" * 60)
    print("TEST 2: X11 Channel Without Forwarding Request (RFC 4254 §6.3.2)")
    print("=" * 60)

    ssh, transport = get_transport(host, port, username, password)

    # Open a normal session first (we need an active channel)
    session = transport.open_session()
    print("  Session opened (no X11 forwarding requested)")

    # Now try to open an X11 channel directly via the transport
    # This crafts a channel open request for type "x11"
    try:
        chan = transport.open_channel(
            "x11",
            src_addr=("127.0.0.1", 6000),  # X11 display address
            dest_addr=("127.0.0.1", 6000),
        )
        if chan:
            print("  [VULNERABLE] Server accepted X11 channel without forwarding request!")
            print("               This violates RFC 4254 Section 6.3.2")
            chan.close()
        else:
            print("  [OK] Server returned None for X11 channel")
    except paramiko.ChannelException as e:
        code, msg = e.args
        print(f"  [OK] Server rejected X11 channel: code={code} msg={msg}")
        print("       (Correct behavior per RFC 4254)")
    except TypeError:
        # paramiko's open_channel for x11 may have different arg handling
        # Try the raw approach
        print("  paramiko API issue — trying raw channel open...")
        try:
            m = paramiko.Message()
            m.add_byte(paramiko.common.cMSG_CHANNEL_OPEN)
            m.add_string("x11")
            m.add_int(transport._next_channel())
            m.add_int(2 * 1024 * 1024)  # window size
            m.add_int(32768)  # max packet
            m.add_string("127.0.0.1")  # originator
            m.add_int(6000)  # originator port
            transport._send_message(m)

            # Wait for response
            time.sleep(1)
            print("  Sent raw x11 channel open request (response in server logs)")
        except Exception as e2:
            print(f"  Raw approach also failed: {e2}")
    except Exception as e:
        print(f"  Error: {e}")

    session.close()
    ssh.close()
    print()


# ---------------------------------------------------------------------------
# Test 3: Channel type fuzzing
# ---------------------------------------------------------------------------

def test_channel_types(host, port, username, password):
    """
    Test how the server handles various channel type requests.
    Some implementations may accept unknown channel types or
    leak information in error responses.
    """
    print("=" * 60)
    print("TEST 3: Channel Type Handling")
    print("=" * 60)

    ssh, transport = get_transport(host, port, username, password)

    channel_types = [
        "session",           # Standard — should work
        "direct-tcpip",      # Standard — tested separately
        "forwarded-tcpip",   # Server-initiated — should reject from client
        "x11",               # X11 — should reject without forwarding setup
        "auth-agent@openssh.com",  # Agent forwarding
        "tun@openssh.com",   # TUN/TAP tunneling
        "",                  # Empty type
        "A" * 256,           # Oversized type name
        "direct-tcpip\x00evil",  # Null byte injection
    ]

    for ctype in channel_types:
        display = ctype[:50] + "..." if len(ctype) > 50 else ctype
        display = repr(display) if not display.isprintable() or not display else display
        try:
            if ctype == "direct-tcpip":
                chan = transport.open_channel(ctype, ("127.0.0.1", 22), ("127.0.0.1", 12345))
            elif ctype == "x11":
                # Use raw message to avoid paramiko validation
                m = paramiko.Message()
                m.add_byte(paramiko.common.cMSG_CHANNEL_OPEN)
                m.add_string(ctype)
                m.add_int(transport._next_channel())
                m.add_int(2 * 1024 * 1024)
                m.add_int(32768)
                m.add_string("127.0.0.1")
                m.add_int(6000)
                transport._send_message(m)
                time.sleep(0.5)
                print(f"  {display:45s} -> sent (raw)")
                continue
            else:
                chan = transport.open_channel(ctype)

            if chan:
                print(f"  {display:45s} -> OPENED (accepted)")
                chan.close()
            else:
                print(f"  {display:45s} -> None (rejected silently)")
        except paramiko.ChannelException as e:
            code, msg = e.args
            print(f"  {display:45s} -> REJECTED code={code} msg={msg}")
        except Exception as e:
            err = str(e)[:60]
            print(f"  {display:45s} -> ERROR: {err}")

    ssh.close()
    print()


# ---------------------------------------------------------------------------
# Test 4: Environment variable injection
# ---------------------------------------------------------------------------

def test_env_injection(host, port, username, password):
    """
    RFC 4254 Section 6.4: Clients can request environment variables
    be set. Test if the server accepts potentially dangerous env vars.
    """
    print("=" * 60)
    print("TEST 4: Environment Variable Injection (RFC 4254 §6.4)")
    print("=" * 60)

    ssh, transport = get_transport(host, port, username, password)

    # Open a session channel
    session = transport.open_session()

    # Try setting various environment variables
    env_vars = [
        ("LANG", "C", "Standard — usually accepted"),
        ("LC_ALL", "C", "Locale — usually accepted"),
        ("PATH", "/tmp:/usr/bin", "PATH override — dangerous if accepted"),
        ("LD_PRELOAD", "/tmp/evil.so", "LD_PRELOAD — very dangerous if accepted"),
        ("LD_LIBRARY_PATH", "/tmp", "LD_LIBRARY_PATH — dangerous if accepted"),
        ("PYTHONPATH", "/tmp", "PYTHONPATH — code injection if accepted"),
        ("HOME", "/tmp", "HOME override"),
        ("SHELL", "/bin/sh", "SHELL override"),
        ("USER", "root", "USER spoofing"),
        ("SSH_ORIGINAL_COMMAND", "cat /etc/shadow", "SSH command injection"),
    ]

    for name, value, desc in env_vars:
        try:
            ok = session.set_environment_variable(name, value)
            if ok:
                print(f"  [ACCEPTED] {name}={value:30s} — {desc}")
            else:
                print(f"  [REJECTED] {name}={value:30s} — {desc}")
        except paramiko.SSHException as e:
            # "channel is not open" or similar
            print(f"  [REJECTED] {name}={value:30s} — {e}")
        except Exception as e:
            print(f"  [ERROR]    {name}={value:30s} — {e}")

    session.close()
    ssh.close()
    print()


# ---------------------------------------------------------------------------
# Test 5: Global requests (tcpip-forward, etc.)
# ---------------------------------------------------------------------------

def test_global_requests(host, port, username, password):
    """
    Test which global requests the server honors.
    tcpip-forward lets us bind ports on the server.
    """
    print("=" * 60)
    print("TEST 5: Global Requests (tcpip-forward)")
    print("=" * 60)

    ssh, transport = get_transport(host, port, username, password)

    # Test: can we request the server to listen on a port and forward to us?
    # This is "remote port forwarding" — tcpip-forward global request
    test_ports = [0, 8888, 9999, 2222]
    for bind_port in test_ports:
        try:
            port_assigned = transport.request_port_forward("127.0.0.1", bind_port)
            if port_assigned:
                print(f"  [ACCEPTED] tcpip-forward 127.0.0.1:{bind_port} -> got port {port_assigned}")
                print(f"             Server is now listening on port {port_assigned} on our behalf!")
                # Cancel it
                transport.cancel_port_forward("127.0.0.1", port_assigned)
                print(f"             (cancelled)")
            else:
                print(f"  [REJECTED] tcpip-forward 127.0.0.1:{bind_port}")
        except paramiko.SSHException as e:
            print(f"  [REJECTED] tcpip-forward 127.0.0.1:{bind_port} — {e}")
        except Exception as e:
            print(f"  [ERROR]    tcpip-forward 127.0.0.1:{bind_port} — {e}")

    ssh.close()
    print()


# ---------------------------------------------------------------------------
# Test 6: Multiple concurrent sessions
# ---------------------------------------------------------------------------

def test_concurrent_sessions(host, port, username, password, max_sessions=20):
    """
    Test how many concurrent channels/sessions the server allows.
    RFC doesn't mandate limits — this tests resource exhaustion potential.
    """
    print("=" * 60)
    print(f"TEST 6: Concurrent Session Limits (up to {max_sessions})")
    print("=" * 60)

    ssh, transport = get_transport(host, port, username, password)

    sessions = []
    for i in range(max_sessions):
        try:
            session = transport.open_session()
            if session:
                sessions.append(session)
            else:
                print(f"  Session {i+1}: returned None")
                break
        except paramiko.ChannelException as e:
            print(f"  Session {i+1}: REJECTED — {e.args}")
            break
        except Exception as e:
            print(f"  Session {i+1}: ERROR — {e}")
            break

    print(f"  Opened {len(sessions)} concurrent sessions")
    if len(sessions) >= max_sessions:
        print(f"  [NOTE] Server allowed all {max_sessions} sessions — no apparent limit")
        print(f"         (potential for resource exhaustion)")
    elif len(sessions) > 0:
        print(f"  [OK] Server limits concurrent sessions to ~{len(sessions)}")

    for s in sessions:
        try:
            s.close()
        except:
            pass
    ssh.close()
    print()


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main():
    if len(sys.argv) < 5:
        print(f"Usage: {sys.argv[0]} <host> <port> <username> <password>")
        sys.exit(1)

    host = sys.argv[1]
    port = int(sys.argv[2])
    username = sys.argv[3]
    password = sys.argv[4]

    print(f"\nSSH Post-Auth Security Probe — {host}:{port} as {username}")
    print(f"Testing findings that require valid credentials\n")

    test_direct_tcpip_spoofing(host, port, username, password)
    test_x11_unrequested(host, port, username, password)
    test_channel_types(host, port, username, password)
    test_env_injection(host, port, username, password)
    test_global_requests(host, port, username, password)
    test_concurrent_sessions(host, port, username, password)

    print("=" * 60)
    print("POST-AUTH PROBE COMPLETE")
    print("=" * 60)


if __name__ == "__main__":
    main()
