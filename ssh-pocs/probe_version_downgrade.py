#!/usr/bin/env python3
"""
Test SSH version downgrade susceptibility.

Checks:
1. Does the server accept SSH-1.x version strings?
2. Does the server accept malformed version strings (no CR/LF)?
3. What does the server do with non-standard version strings?

This tests the "SSH Version Downgrade via Compatibility Flag Manipulation"
finding from the ssh-report (lead #3, RFC 4253 Section 5.1/5.2).

Usage: python probe_version_downgrade.py <host> [port]
"""

import socket
import sys
import time


def test_version_string(host, port, version_string, label):
    """Send a specific version string and observe server response."""
    print(f"\n  --- {label} ---")
    print(f"  Sending: {repr(version_string)}")

    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(5)
        sock.connect((host, port))

        # Read server banner first
        banner = b""
        while not banner.endswith(b"\n"):
            chunk = sock.recv(1024)
            if not chunk:
                break
            banner += chunk
        server_banner = banner.decode("utf-8", errors="replace").strip()
        print(f"  Server banner: {server_banner}")

        # Send our crafted version string
        sock.sendall(version_string)

        # Wait and read response
        time.sleep(0.5)
        sock.settimeout(3)
        try:
            response = sock.recv(4096)
            if response:
                # Check if it's a KEXINIT (server accepted our version)
                # SSH binary packet starts with uint32 length
                if len(response) >= 5:
                    import struct
                    pkt_len = struct.unpack(">I", response[:4])[0]
                    pad_len = response[4]
                    if len(response) >= 6:
                        msg_type = response[5]
                        if msg_type == 20:
                            print(f"  [!!] Server sent KEXINIT — accepted our version string!")
                            return "accepted"
                        elif msg_type == 1:  # SSH_MSG_DISCONNECT
                            reason = struct.unpack(">I", response[6:10])[0] if len(response) >= 10 else 0
                            print(f"  Server sent DISCONNECT (reason={reason})")
                            return "disconnected"
                        else:
                            print(f"  Server sent message type {msg_type}")
                            return "unknown"
                # Maybe it's a text error message
                text = response.decode("utf-8", errors="replace").strip()
                if text:
                    print(f"  Server response (text): {text}")
                    return "text_error"
            else:
                print(f"  Server closed connection (no response)")
                return "closed"
        except socket.timeout:
            print(f"  Server sent nothing (timeout) — likely processing or hung")
            return "timeout"

        sock.close()
    except ConnectionResetError:
        print(f"  Connection reset by server")
        return "reset"
    except Exception as e:
        print(f"  Error: {e}")
        return "error"


def main():
    if len(sys.argv) < 2:
        print(f"Usage: {sys.argv[0]} <host> [port]")
        sys.exit(1)

    host = sys.argv[1]
    port = int(sys.argv[2]) if len(sys.argv) > 2 else 22

    print("=" * 60)
    print("SSH Version Downgrade Susceptibility Test")
    print(f"Target: {host}:{port}")
    print("=" * 60)

    results = {}

    # Test 1: Normal SSH-2.0 version (baseline)
    results["normal"] = test_version_string(
        host, port, b"SSH-2.0-TestClient\r\n",
        "Baseline: valid SSH-2.0 version"
    )

    # Test 2: SSH-1.99 compatibility version
    results["compat_1.99"] = test_version_string(
        host, port, b"SSH-1.99-TestClient\r\n",
        "SSH-1.99 compatibility mode"
    )

    # Test 3: SSH-1.5 (old protocol)
    results["ssh1"] = test_version_string(
        host, port, b"SSH-1.5-TestClient\r\n",
        "SSH-1.5 (legacy protocol)"
    )

    # Test 4: Version string without CR (just LF)
    results["no_cr"] = test_version_string(
        host, port, b"SSH-2.0-TestClient\n",
        "SSH-2.0 without CR (LF only)"
    )

    # Test 5: Version string without CR/LF
    results["no_crlf"] = test_version_string(
        host, port, b"SSH-2.0-TestClient",
        "SSH-2.0 without any line terminator"
    )

    # Test 6: Extra-long version string (overflow attempt)
    long_sw = "A" * 300
    results["long"] = test_version_string(
        host, port, f"SSH-2.0-{long_sw}\r\n".encode(),
        "SSH-2.0 with 300-char software version"
    )

    # Summary
    print("\n" + "=" * 60)
    print("SUMMARY")
    print("=" * 60)

    if results.get("compat_1.99") == "accepted":
        print("[FINDING] Server accepts SSH-1.99 — SSH-1 compat mode enabled!")
        print("         Downgrade attack may be possible via MITM banner rewrite")
    else:
        print("[OK] Server does not accept SSH-1.99 compatibility mode")

    if results.get("ssh1") == "accepted":
        print("[FINDING] Server accepts SSH-1.5 — legacy SSH-1 is enabled!")
    else:
        print("[OK] Server rejects SSH-1.5")

    if results.get("no_cr") == "accepted":
        print("[NOTE] Server accepts LF-only line endings (lenient parsing)")
    if results.get("no_crlf") in ("accepted", "timeout"):
        print("[NOTE] Server waits for line terminator (correct behavior)")


if __name__ == "__main__":
    main()
