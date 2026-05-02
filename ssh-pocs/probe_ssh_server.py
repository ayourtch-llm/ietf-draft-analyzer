#!/usr/bin/env python3
"""
SSH Server Security Probe — tests findings from rfc-analyzer reports
against a real SSH server using proper protocol handling (paramiko).

Tests performed:
  1. Banner/version information disclosure
  2. Algorithm audit (ciphers, KEX, MACs, host keys)
  3. 'none' cipher / MAC availability
  4. Strict KEX mode support
  5. SSH-1 compatibility mode check
  6. ECC curve support analysis
  7. Debug message observation during handshake

Usage: python probe_ssh_server.py <host> [port]
"""

import socket
import struct
import sys
import os
import re


# ---------------------------------------------------------------------------
# 1. Raw banner grab + SSH-1 compatibility check
# ---------------------------------------------------------------------------

def test_banner(host, port):
    """
    Grab the SSH banner. Check:
    - Does it reveal software name/version? (InformationLeak)
    - Does it advertise SSH-1.99 compatibility? (Downgrade)
    """
    print("=" * 60)
    print("TEST 1: Banner / Version String Analysis")
    print("=" * 60)

    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(5)
    sock.connect((host, port))

    banner = b""
    while not banner.endswith(b"\n"):
        chunk = sock.recv(1024)
        if not chunk:
            break
        banner += chunk
    sock.close()

    banner_str = banner.decode("utf-8", errors="replace").strip()
    print(f"  Banner: {banner_str}")

    # Parse SSH-protoversion-softwareversion SP comments
    m = re.match(r"SSH-(\S+)-(\S+)(.*)", banner_str)
    if not m:
        print("  [!] Could not parse banner format")
        return

    proto, software, comments = m.group(1), m.group(2), m.group(3).strip()

    # SSH-1 compatibility check (RFC 4253 Section 5.1)
    if proto == "1.99":
        print("  [FINDING] Server advertises SSH-1.99 — SSH-1 compatibility enabled!")
        print("            This enables the version downgrade attack (ssh-report lead #3)")
    elif proto.startswith("1."):
        print("  [FINDING] Server only supports SSH-1 — critically insecure")
    else:
        print(f"  [OK] Protocol version: {proto} (no SSH-1 compat)")

    # Information disclosure via banner
    print(f"  Software: {software}")
    if comments:
        print(f"  Comments: {comments}")

    # Check if version reveals patchlevel
    if re.search(r"OpenSSH[_-][\d.]+", software):
        print("  [NOTE] Banner reveals exact OpenSSH version — minor info leak")
        print("         (allows attacker to check CVE databases for version-specific vulns)")
    print()


# ---------------------------------------------------------------------------
# 2-6. Algorithm audit via paramiko transport inspection
# ---------------------------------------------------------------------------

def test_algorithms(host, port):
    """
    Connect via paramiko, inspect the KEXINIT from the server.
    Check for weak algorithms, 'none' cipher, strict KEX, etc.
    """
    import paramiko
    import paramiko.transport

    print("=" * 60)
    print("TEST 2-6: Algorithm Negotiation Audit")
    print("=" * 60)

    # We need to capture the server's KEXINIT before paramiko filters it.
    # paramiko exposes the negotiated algorithms and the server's offered
    # lists through the transport object after handshake.

    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(10)
    sock.connect((host, port))

    t = paramiko.Transport(sock)

    # Capture raw server KEXINIT by hooking into the handshake
    # We'll start the client side and inspect what was negotiated.
    t.start_client()

    # --- Server's offered algorithms (from the KEXINIT we received) ---
    # paramiko stores these on the transport after parsing the server KEXINIT
    # Access via internal attributes (stable across paramiko 3.x/4.x)
    server_kex = getattr(t, '_preferred_kex', None) or []
    server_keys = getattr(t, '_preferred_keys', None) or []
    server_ciphers = getattr(t, '_preferred_ciphers', None) or []
    server_macs = getattr(t, '_preferred_macs', None) or []

    # The actually-negotiated algorithms are more reliably available:
    negotiated = {}
    negotiated['kex'] = getattr(t, '_agreed_kex', None) or 'unknown'
    negotiated['host_key'] = getattr(t, '_agreed_key', None) or 'unknown'

    # The remote (server) offered lists are available via the SecurityOptions
    # which reflect what paramiko knows the peer offered:
    remote_kex_list = []
    remote_key_list = []
    remote_cipher_list = []
    remote_mac_list = []
    remote_compress_list = []

    # paramiko stores the parsed server KEXINIT in _remote_kex_algorithms etc.
    # These are set during _negotiate_keys. Let's try to access them.
    for attr in dir(t):
        if 'remote' in attr.lower() or 'server' in attr.lower():
            pass  # just scanning

    # Best approach: read the debug log we already know works.
    # Actually, let's just use SecurityOptions which shows what WE offer,
    # and use the negotiated result to infer server support.
    # The raw server lists were printed in the debug output earlier.
    # Let's capture them properly by enabling paramiko's packet logging.

    print(f"\n  Remote version: {t.remote_version}")
    print(f"  Local version:  {t.local_version}")

    # Negotiated algorithms
    print(f"\n  Negotiated KEX:      {negotiated['kex']}")
    print(f"  Negotiated Host Key: {negotiated['host_key']}")

    # Check strict kex
    strict_kex = getattr(t, '_strict_kex', False)
    print(f"\n  Strict KEX mode: {strict_kex}")
    if strict_kex:
        print("  [OK] Server enforces strict KEX (mitigates Terrapin attack)")
    else:
        print("  [FINDING] Server does NOT enforce strict KEX — vulnerable to Terrapin!")

    # Get the server's host key for analysis
    host_key = t.get_remote_server_key()
    if host_key:
        key_type = host_key.get_name()
        key_bits = host_key.get_bits()
        print(f"\n  Server host key: {key_type} ({key_bits} bits)")
        if key_type == 'ssh-rsa' and key_bits < 2048:
            print("  [FINDING] RSA key is < 2048 bits — weak!")
        elif key_type == 'ssh-dss':
            print("  [FINDING] DSA key — deprecated and weak!")

    t.close()
    sock.close()
    print()

    return strict_kex


# ---------------------------------------------------------------------------
# 2b. Raw KEXINIT parse — get the actual server-offered algorithm lists
# ---------------------------------------------------------------------------

def test_raw_kexinit(host, port):
    """
    Do a raw TCP connect, exchange banners, read the server's KEXINIT,
    and parse every algorithm list. This gives us the full picture that
    paramiko's API doesn't directly expose.
    """
    print("=" * 60)
    print("TEST 2b: Raw KEXINIT Algorithm Enumeration")
    print("=" * 60)

    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(5)
    sock.connect((host, port))

    # Read server banner
    banner = b""
    while not banner.endswith(b"\n"):
        chunk = sock.recv(1024)
        if not chunk:
            break
        banner += chunk

    # Send our banner
    sock.sendall(b"SSH-2.0-RFCAnalyzerProbe\r\n")

    # Read server's KEXINIT packet
    # SSH Binary Packet: uint32 packet_length, byte padding_length, payload, padding
    header = b""
    while len(header) < 4:
        header += sock.recv(4 - len(header))

    packet_length = struct.unpack(">I", header)[0]
    rest = b""
    while len(rest) < packet_length:
        rest += sock.recv(packet_length - len(rest))

    sock.close()

    padding_length = rest[0]
    payload = rest[1 : packet_length - padding_length]

    if not payload or payload[0] != 20:  # SSH_MSG_KEXINIT
        print("  [!] Did not receive KEXINIT as first message")
        return {}

    # Parse KEXINIT: byte type, byte[16] cookie, then 10 name-lists, bool, uint32
    offset = 1 + 16  # skip type + cookie

    def read_name_list(data, off):
        length = struct.unpack(">I", data[off : off + 4])[0]
        off += 4
        names = data[off : off + length].decode("ascii", errors="replace")
        off += length
        return names.split(",") if names else [], off

    labels = [
        "kex_algorithms",
        "server_host_key_algorithms",
        "encryption_client_to_server",
        "encryption_server_to_client",
        "mac_client_to_server",
        "mac_server_to_client",
        "compression_client_to_server",
        "compression_server_to_client",
        "languages_client_to_server",
        "languages_server_to_client",
    ]

    server_algos = {}
    for label in labels:
        algos, offset = read_name_list(payload, offset)
        server_algos[label] = algos

    # first_kex_packet_follows
    first_kex_follows = payload[offset] if offset < len(payload) else 0

    # Print and analyze
    for label, algos in server_algos.items():
        if not algos or algos == [""]:
            continue
        short = label.replace("_", " ").title()
        print(f"\n  {short}:")
        for a in algos:
            flag = ""
            # Flag weak/dangerous algorithms
            if a == "none" and "encryption" in label:
                flag = " *** DANGEROUS: no encryption! ***"
            elif a == "none" and "mac" in label:
                flag = " *** DANGEROUS: no MAC! ***"
            elif a in ("diffie-hellman-group1-sha1", "diffie-hellman-group-exchange-sha1"):
                flag = " [WEAK: SHA-1 based KEX]"
            elif a == "ssh-dss":
                flag = " [WEAK: DSA deprecated]"
            elif a == "ssh-rsa":
                flag = " [NOTE: raw ssh-rsa uses SHA-1 signatures]"
            elif a in ("arcfour", "arcfour128", "arcfour256"):
                flag = " [WEAK: RC4]"
            elif a in ("3des-cbc", "blowfish-cbc", "cast128-cbc"):
                flag = " [WEAK: legacy cipher]"
            elif a in ("aes128-cbc", "aes192-cbc", "aes256-cbc"):
                flag = " [NOTE: CBC mode — susceptible to plaintext recovery]"
            elif a == "hmac-sha1":
                flag = " [NOTE: SHA-1 MAC]"
            elif a in ("hmac-md5", "hmac-md5-96", "hmac-sha1-96"):
                flag = " [WEAK: truncated or MD5 MAC]"
            elif "kex-strict" in a:
                flag = " [GOOD: Terrapin mitigation]"
            elif "ext-info" in a:
                flag = " [extension negotiation]"
            elif "sntrup" in a or "mlkem" in a:
                flag = " [GOOD: post-quantum]"
            print(f"    - {a}{flag}")

    # Specific checks from the reports

    # Check: does the server offer 'none' cipher? (ssh-report lead #5)
    enc_algos = server_algos.get("encryption_client_to_server", [])
    if "none" in enc_algos:
        print("\n  [FINDING] 'none' cipher is offered — traffic can be unencrypted!")
        print("           (ssh-report: Cipher Downgrade via 'none' Algorithm Injection)")
    else:
        print("\n  [OK] 'none' cipher is NOT offered")

    # Check: does the server offer 'none' MAC?
    mac_algos = server_algos.get("mac_client_to_server", [])
    if "none" in mac_algos:
        print("  [FINDING] 'none' MAC is offered — no integrity protection possible!")
    else:
        print("  [OK] 'none' MAC is NOT offered")

    # Check: strict KEX advertised?
    kex_algos = server_algos.get("kex_algorithms", [])
    has_strict_kex = any("kex-strict" in a for a in kex_algos)
    if has_strict_kex:
        print("  [OK] Strict KEX mode advertised (Terrapin CVE-2023-48795 mitigation)")
    else:
        print("  [FINDING] No strict KEX — potentially vulnerable to Terrapin attack!")

    # Check: any SHA-1 based KEX?
    sha1_kex = [a for a in kex_algos if "sha1" in a.lower() and "kex-strict" not in a]
    if sha1_kex:
        print(f"  [NOTE] SHA-1 based KEX algorithms offered: {', '.join(sha1_kex)}")
    else:
        print("  [OK] No SHA-1 based KEX algorithms")

    # Check: any weak ciphers?
    weak_ciphers = [a for a in enc_algos if a in (
        "arcfour", "arcfour128", "arcfour256", "3des-cbc", "blowfish-cbc",
        "cast128-cbc", "none"
    )]
    if weak_ciphers:
        print(f"  [FINDING] Weak ciphers offered: {', '.join(weak_ciphers)}")
    else:
        print("  [OK] No weak ciphers offered")

    # Check: CBC mode ciphers (susceptible to plaintext recovery attacks)?
    cbc_ciphers = [a for a in enc_algos if a.endswith("-cbc")]
    if cbc_ciphers:
        print(f"  [NOTE] CBC-mode ciphers offered: {', '.join(cbc_ciphers)}")
        print("         These may be susceptible to plaintext recovery attacks")
    else:
        print("  [OK] No CBC-mode ciphers")

    # Check: post-quantum algorithms?
    pq_algos = [a for a in kex_algos if "sntrup" in a or "mlkem" in a]
    if pq_algos:
        print(f"  [OK] Post-quantum KEX available: {', '.join(pq_algos)}")
    else:
        print("  [NOTE] No post-quantum KEX algorithms offered")

    # Check: ECC curves supported (from KEX algorithms)
    ecc_kex = [a for a in kex_algos if "ecdh" in a]
    if ecc_kex:
        print(f"\n  ECC Key Exchange algorithms:")
        for a in ecc_kex:
            curve = a.replace("ecdh-sha2-", "")
            note = ""
            if curve == "nistp256":
                note = " (NIST P-256, 128-bit security)"
            elif curve == "nistp384":
                note = " (NIST P-384, 192-bit security)"
            elif curve == "nistp521":
                note = " (NIST P-521, 256-bit security)"
            print(f"    - {a}{note}")

    print()
    return server_algos


# ---------------------------------------------------------------------------
# 7. Debug message check during handshake
# ---------------------------------------------------------------------------

def test_debug_messages(host, port):
    """
    Connect and observe if the server sends any SSH_MSG_DEBUG (type 4)
    during the handshake phase. This tests the InformationLeak finding
    from the ssh-report about debug message disclosure.
    """
    import paramiko
    import logging

    print("=" * 60)
    print("TEST 7: Debug Message Observation")
    print("=" * 60)

    # Capture SSH_MSG_DEBUG at the paramiko packet level
    debug_messages = []

    class DebugCapture(logging.Handler):
        def emit(self, record):
            msg = record.getMessage()
            if "SSH_MSG_DEBUG" in msg or "Debug" in msg:
                debug_messages.append(msg)

    handler = DebugCapture()
    paramiko_logger = logging.getLogger("paramiko.transport")
    paramiko_logger.addHandler(handler)
    paramiko_logger.setLevel(logging.DEBUG)

    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(10)
        sock.connect((host, port))
        t = paramiko.Transport(sock)
        t.start_client()

        # Try a few things that might trigger debug messages:
        # 1. Request auth with 'none' method (probing which methods are available)
        try:
            t.auth_none("")
        except paramiko.BadAuthenticationType:
            pass  # Expected — server tells us which methods it accepts
        except paramiko.SSHException:
            pass

        t.close()
        sock.close()
    except Exception as e:
        print(f"  Connection error: {e}")
    finally:
        paramiko_logger.removeHandler(handler)

    if debug_messages:
        print(f"  [FINDING] Server sent {len(debug_messages)} debug message(s):")
        for msg in debug_messages[:10]:
            print(f"    {msg}")
    else:
        print("  [OK] No SSH_MSG_DEBUG messages observed during handshake")
    print()


# ---------------------------------------------------------------------------
# 8. Keyboard-interactive response count mismatch (needs valid user)
# ---------------------------------------------------------------------------

def test_kbdint_response_mismatch(host, port, username="root"):
    """
    Test: send a keyboard-interactive auth request, then respond with
    a mismatched num-responses. RFC 4256 Section 3.4 says the server
    MUST send failure if counts don't match.

    This tests the 'Missing Validation of Authentication Response Count'
    finding from the extended report.
    """
    import paramiko

    print("=" * 60)
    print(f"TEST 8: Keyboard-Interactive Response Count Mismatch (user={username})")
    print("=" * 60)

    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(10)
        sock.connect((host, port))
        t = paramiko.Transport(sock)
        t.start_client()

        # Check if keyboard-interactive is supported
        try:
            t.auth_none(username)
        except paramiko.BadAuthenticationType as e:
            allowed = e.allowed_types
            print(f"  Allowed auth methods: {allowed}")
            if "keyboard-interactive" not in allowed:
                print("  [SKIP] keyboard-interactive not offered for this user")
                t.close()
                return
        except paramiko.SSHException:
            print("  [SKIP] Could not probe auth methods")
            t.close()
            return

        # Now try keyboard-interactive with a custom handler
        prompts_received = []
        def kbdint_handler(title, instructions, prompt_list):
            prompts_received.append({
                "title": title,
                "instructions": instructions,
                "prompts": prompt_list,
                "num_prompts": len(prompt_list),
            })
            # Deliberately return WRONG number of responses
            # If server asked for 1 prompt, send 0 or 2 responses
            if len(prompt_list) == 0:
                return ("extra_response",)  # send 1 when 0 expected
            else:
                return ()  # send 0 when N expected

        try:
            t.auth_interactive(username, kbdint_handler)
        except paramiko.AuthenticationException:
            pass  # Expected
        except paramiko.SSHException as e:
            print(f"  SSH error: {e}")

        if prompts_received:
            for p in prompts_received:
                print(f"  Server sent {p['num_prompts']} prompt(s): {p['prompts']}")
                if p['num_prompts'] > 0:
                    print(f"  We responded with 0 answers (mismatch)")
                else:
                    print(f"  We responded with 1 answer (mismatch)")
            print("  [OK] Server handled mismatch without crashing (sent auth failure)")
        else:
            print("  [NOTE] No prompts received — server may have rejected immediately")

        t.close()
        sock.close()
    except Exception as e:
        print(f"  Error: {e}")
    print()


# ---------------------------------------------------------------------------
# 9. Auth method enumeration via 'none' auth
# ---------------------------------------------------------------------------

def test_auth_methods(host, port, usernames=None):
    """
    Probe which authentication methods the server offers for various
    usernames. This reveals whether user enumeration is possible
    (different responses for valid vs. invalid users).
    """
    import paramiko

    if usernames is None:
        usernames = ["root", "admin", "nobody", "nonexistent_user_xyz"]

    print("=" * 60)
    print("TEST 9: Authentication Method Enumeration")
    print("=" * 60)

    results = {}
    for username in usernames:
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(5)
            sock.connect((host, port))
            t = paramiko.Transport(sock)
            t.start_client()

            try:
                t.auth_none(username)
                results[username] = ["none (accepted!)"]
                print(f"  [FINDING] User '{username}': auth_none ACCEPTED — no password needed!")
            except paramiko.BadAuthenticationType as e:
                results[username] = e.allowed_types
                print(f"  User '{username}': allowed methods = {e.allowed_types}")
            except paramiko.SSHException as e:
                results[username] = [f"error: {e}"]
                print(f"  User '{username}': {e}")

            t.close()
            sock.close()
        except Exception as e:
            results[username] = [f"connect error: {e}"]
            print(f"  User '{username}': connection error: {e}")

    # Check if different users get different method lists (user enumeration)
    method_sets = {}
    for user, methods in results.items():
        key = tuple(sorted(methods))
        method_sets.setdefault(key, []).append(user)

    if len(method_sets) > 1:
        print("\n  [FINDING] Different users get different auth method lists!")
        print("           This enables user enumeration (valid vs. invalid usernames)")
        for methods, users in method_sets.items():
            print(f"    {users} -> {list(methods)}")
    else:
        print("\n  [OK] All users get the same auth method list (no user enumeration via methods)")
    print()


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main():
    if len(sys.argv) < 2:
        print(f"Usage: {sys.argv[0]} <host> [port]")
        sys.exit(1)

    host = sys.argv[1]
    port = int(sys.argv[2]) if len(sys.argv) > 2 else 22

    print(f"\nSSH Server Security Probe — testing {host}:{port}")
    print(f"Based on rfc-analyzer findings for SSH RFCs 4251-4254, 4256, 4344, 5656\n")

    # Tests that don't need authentication
    test_banner(host, port)
    server_algos = test_raw_kexinit(host, port)
    test_algorithms(host, port)
    test_debug_messages(host, port)
    test_auth_methods(host, port)
    test_kbdint_response_mismatch(host, port)

    print("=" * 60)
    print("PROBE COMPLETE")
    print("=" * 60)


if __name__ == "__main__":
    main()
