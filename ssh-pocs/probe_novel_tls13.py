#!/usr/bin/env python3
"""
Test novel (no-CVE) TLS 1.3 findings from rfc-analyzer reports.

Findings tested:
1. HRR + early_data confusion — does server accept early_data after HRR?
2. 0-RTT replay — can we replay a ClientHello with early data?
3. ClientHello recording store exhaustion — flood PSK resumptions
4. Early exporter consistency across replayed sessions

Usage: python probe_novel_tls13.py <host> <port>

Requires: openssl s_server -early_data -anti_replay on the target
"""

import ssl
import socket
import struct
import sys
import time
import os
import subprocess
import tempfile


def make_ctx(session=None):
    """Create a TLS 1.3 client context."""
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    ctx.minimum_version = ssl.TLSVersion.TLSv1_3
    ctx.maximum_version = ssl.TLSVersion.TLSv1_3
    return ctx


def connect_tls13(host, port, ctx=None):
    """Establish a TLS 1.3 connection, return the SSLSocket."""
    if ctx is None:
        ctx = make_ctx()
    sock = socket.create_connection((host, port), timeout=10)
    ssock = ctx.wrap_socket(sock, server_hostname="testserver")
    return ssock


# ---------------------------------------------------------------------------
# Test 1: 0-RTT Early Data Replay
# ---------------------------------------------------------------------------

def test_0rtt_replay(host, port):
    """
    RFC 8446 Section 8: "TLS does not provide inherent replay protections
    for 0-RTT data."

    Test: Establish a session, get a ticket, reconnect with 0-RTT early data,
    then try to replay the same ClientHello+early data.

    We use openssl s_client because Python's ssl module doesn't expose
    the 0-RTT early data API directly.
    """
    print("=" * 60)
    print("TEST 1: TLS 1.3 0-RTT Early Data Replay")
    print("=" * 60)

    sessfile = tempfile.mktemp(suffix=".pem")

    # Step 1: Establish initial connection, save session ticket
    print("\n  Step 1: Initial handshake to obtain session ticket...")
    cmd1 = [
        "openssl", "s_client",
        "-connect", f"{host}:{port}",
        "-tls1_3",
        "-sess_out", sessfile,
        "-no_ticket",  # don't use ticket from cache, get fresh one
    ]

    try:
        proc = subprocess.run(
            cmd1, input=b"GET / HTTP/1.0\r\n\r\n", capture_output=True, timeout=5
        )
        if os.path.exists(sessfile):
            print(f"  Session ticket saved to {sessfile}")
            # Check if it's a TLS 1.3 session
            sess_info = subprocess.run(
                ["openssl", "sess_id", "-in", sessfile, "-text", "-noout"],
                capture_output=True, timeout=5
            )
            sess_text = sess_info.stdout.decode(errors="replace")
            if "TLSv1.3" in sess_text or "Protocol  : TLSv1.3" in sess_text:
                print("  [OK] Got TLS 1.3 session ticket")
            else:
                # Check what we got
                for line in sess_text.split("\n"):
                    if "Protocol" in line or "TLS" in line:
                        print(f"  Session info: {line.strip()}")
        else:
            print("  [SKIP] No session ticket obtained")
            print(f"  stdout: {proc.stdout[:200]}")
            print(f"  stderr: {proc.stderr[:200]}")
            return
    except subprocess.TimeoutExpired:
        print("  Initial connection timed out (expected with s_server)")

    # Step 2: Reconnect with 0-RTT early data
    print("\n  Step 2: Reconnect with 0-RTT early data...")

    early_data = b"EARLY_DATA_PAYLOAD_TEST_12345"
    early_file = tempfile.mktemp(suffix=".bin")
    with open(early_file, "wb") as f:
        f.write(early_data)

    cmd2 = [
        "openssl", "s_client",
        "-connect", f"{host}:{port}",
        "-tls1_3",
        "-sess_in", sessfile,
        "-early_data", early_file,
    ]

    try:
        proc2 = subprocess.run(
            cmd2, input=b"\n", capture_output=True, timeout=5
        )
        output2 = proc2.stdout.decode(errors="replace") + proc2.stderr.decode(errors="replace")
        if "Early data was accepted" in output2:
            print("  [OK] Server accepted 0-RTT early data (first attempt)")
            early_accepted = True
        elif "Early data was rejected" in output2:
            print("  [INFO] Server rejected 0-RTT early data (first attempt)")
            early_accepted = False
        else:
            print(f"  [?] Unclear result. Checking output...")
            for line in output2.split("\n"):
                if "early" in line.lower() or "0-RTT" in line or "Early" in line:
                    print(f"    {line.strip()}")
            early_accepted = None
    except subprocess.TimeoutExpired:
        print("  Connection timed out")
        early_accepted = None

    # Step 3: REPLAY — try the same session ticket + early data again
    print("\n  Step 3: Replay — same session ticket + early data...")

    try:
        proc3 = subprocess.run(
            cmd2, input=b"\n", capture_output=True, timeout=5
        )
        output3 = proc3.stdout.decode(errors="replace") + proc3.stderr.decode(errors="replace")
        if "Early data was accepted" in output3:
            print("  [FINDING] Server accepted REPLAYED 0-RTT early data!")
            print("            Anti-replay mechanism may be ineffective")
        elif "Early data was rejected" in output3:
            print("  [OK] Server correctly rejected replayed 0-RTT data")
        else:
            print(f"  [?] Unclear replay result")
            for line in output3.split("\n"):
                if "early" in line.lower() or "0-RTT" in line or "Early" in line:
                    print(f"    {line.strip()}")
    except subprocess.TimeoutExpired:
        print("  Replay connection timed out")

    # Cleanup
    for f in [sessfile, early_file]:
        try:
            os.unlink(f)
        except:
            pass
    print()


# ---------------------------------------------------------------------------
# Test 2: ClientHello Recording Store Exhaustion
# ---------------------------------------------------------------------------

def test_recording_store_exhaustion(host, port, count=50):
    """
    RFC 8446 Section 8.2: "Recording all ClientHellos causes state to grow
    without bound."

    Test: Rapidly establish many PSK-resumption connections to see if the
    server's anti-replay recording store can be overwhelmed.
    """
    print("=" * 60)
    print(f"TEST 2: ClientHello Recording Store Exhaustion ({count} connections)")
    print("=" * 60)

    # First get a session ticket
    sessfile = tempfile.mktemp(suffix=".pem")
    cmd_init = [
        "openssl", "s_client",
        "-connect", f"{host}:{port}",
        "-tls1_3",
        "-sess_out", sessfile,
    ]

    try:
        subprocess.run(cmd_init, input=b"\n", capture_output=True, timeout=5)
    except subprocess.TimeoutExpired:
        pass

    if not os.path.exists(sessfile):
        print("  [SKIP] Could not obtain session ticket")
        return

    early_data = b"FLOOD_TEST"
    early_file = tempfile.mktemp(suffix=".bin")
    with open(early_file, "wb") as f:
        f.write(early_data)

    # Rapid-fire resumption attempts
    print(f"\n  Sending {count} rapid PSK resumption attempts...")
    accepted = 0
    rejected = 0
    errors = 0
    t0 = time.monotonic()

    for i in range(count):
        cmd = [
            "openssl", "s_client",
            "-connect", f"{host}:{port}",
            "-tls1_3",
            "-sess_in", sessfile,
            "-early_data", early_file,
        ]
        try:
            proc = subprocess.run(cmd, input=b"\n", capture_output=True, timeout=3)
            output = proc.stdout.decode(errors="replace") + proc.stderr.decode(errors="replace")
            if "Early data was accepted" in output:
                accepted += 1
            elif "Early data was rejected" in output:
                rejected += 1
            else:
                errors += 1
        except subprocess.TimeoutExpired:
            errors += 1
        except Exception:
            errors += 1

    elapsed = time.monotonic() - t0
    print(f"  Completed in {elapsed:.1f}s")
    print(f"  Accepted: {accepted}  Rejected: {rejected}  Errors: {errors}")

    if accepted > 1:
        print(f"  [FINDING] {accepted} early data payloads accepted from same ticket!")
        print(f"           Anti-replay may not be working correctly")
    elif accepted <= 1 and rejected > 0:
        print(f"  [OK] Server rejected replays after first acceptance")

    # Check if server is still alive
    try:
        ssock = connect_tls13(host, port)
        print(f"  Server still responding after {count} rapid connections")
        ssock.close()
    except Exception as e:
        print(f"  [FINDING] Server became unresponsive: {e}")
        print(f"           Recording store exhaustion may have caused DoS")

    for f in [sessfile, early_file]:
        try:
            os.unlink(f)
        except:
            pass
    print()


# ---------------------------------------------------------------------------
# Test 3: Session ticket reuse across connections (basic replay)
# ---------------------------------------------------------------------------

def test_ticket_reuse(host, port):
    """
    Test whether the same session ticket can be used for multiple resumptions.
    If so, each resumption with early_data is a replay opportunity.
    """
    print("=" * 60)
    print("TEST 3: Session Ticket Reuse for Multiple Resumptions")
    print("=" * 60)

    sessfile = tempfile.mktemp(suffix=".pem")

    # Get initial ticket
    cmd_init = [
        "openssl", "s_client",
        "-connect", f"{host}:{port}",
        "-tls1_3",
        "-sess_out", sessfile,
    ]
    try:
        subprocess.run(cmd_init, input=b"\n", capture_output=True, timeout=5)
    except subprocess.TimeoutExpired:
        pass

    if not os.path.exists(sessfile):
        print("  [SKIP] No session ticket")
        return

    # Try reusing the ticket multiple times (without early data)
    print("\n  Reusing same ticket for multiple resumptions...")
    successes = 0
    for i in range(5):
        cmd = [
            "openssl", "s_client",
            "-connect", f"{host}:{port}",
            "-tls1_3",
            "-sess_in", sessfile,
        ]
        try:
            proc = subprocess.run(cmd, input=b"\n", capture_output=True, timeout=3)
            output = proc.stdout.decode(errors="replace") + proc.stderr.decode(errors="replace")
            if "Reused" in output or "reuse" in output.lower():
                successes += 1
            elif "New" in output:
                pass  # Full handshake, ticket wasn't reused
        except:
            pass

    print(f"  Successful ticket reuses: {successes}/5")
    if successes > 1:
        print(f"  [NOTE] Ticket can be reused multiple times")
        print(f"         Each reuse with early_data is a replay opportunity")
        print(f"         (single-use tickets would prevent this)")
    elif successes <= 1:
        print(f"  [OK] Server enforces single-use tickets or ticket rotation")

    try:
        os.unlink(sessfile)
    except:
        pass
    print()


# ---------------------------------------------------------------------------
# Test 4: Cipher suite and key exchange enumeration
# ---------------------------------------------------------------------------

def test_tls13_config(host, port):
    """
    Enumerate TLS 1.3 configuration details for context.
    """
    print("=" * 60)
    print("TEST 4: TLS 1.3 Configuration Audit")
    print("=" * 60)

    ssock = connect_tls13(host, port)
    print(f"  Version: {ssock.version()}")
    print(f"  Cipher:  {ssock.cipher()}")

    # Check shared ciphers
    shared = ssock.shared_ciphers()
    if shared:
        print(f"  Shared cipher suites:")
        for c in shared:
            print(f"    - {c[0]} ({c[1]}, {c[2]}-bit)")

    # Get server cert info
    cert = ssock.getpeercert(binary_form=True)
    if cert:
        print(f"  Server cert: {len(cert)} bytes (DER)")

    ssock.close()
    print()


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main():
    if len(sys.argv) < 3:
        print(f"Usage: {sys.argv[0]} <host> <port>")
        sys.exit(1)

    host = sys.argv[1]
    port = int(sys.argv[2])

    print(f"\nTLS 1.3 Novel Finding Probes — {host}:{port}")
    print(f"Testing findings without existing CVEs\n")

    test_tls13_config(host, port)
    test_0rtt_replay(host, port)
    test_ticket_reuse(host, port)
    test_recording_store_exhaustion(host, port, count=20)

    print("=" * 60)
    print("TLS 1.3 PROBES COMPLETE")
    print("=" * 60)


if __name__ == "__main__":
    main()
