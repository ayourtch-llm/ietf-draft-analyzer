#!/usr/bin/env python3
"""
Proper test for SSH 'none' cipher downgrade (ssh-report lead #5).

The generated PoC was broken because it didn't send a banner or use
proper SSH binary packet framing. This version does it correctly:

1. Exchange banners
2. Send a properly framed KEXINIT that ONLY offers 'none' as cipher
3. Read the server's KEXINIT
4. Check if the server would have agreed to 'none'

We also test what happens if we offer only weak/deprecated algorithms.

Usage: python probe_cipher_downgrade.py <host> [port]
"""

import socket
import struct
import os
import sys


def encode_name_list(names):
    """Encode a list of algorithm names as SSH name-list (uint32 length + ascii)."""
    s = ",".join(names).encode("ascii")
    return struct.pack(">I", len(s)) + s


def build_kexinit(ciphers_c2s, ciphers_s2c=None, kex=None, host_keys=None,
                  macs=None, compression=None):
    """Build a valid SSH_MSG_KEXINIT payload."""
    if ciphers_s2c is None:
        ciphers_s2c = ciphers_c2s
    if kex is None:
        kex = ["curve25519-sha256", "ecdh-sha2-nistp256",
               "diffie-hellman-group14-sha256"]
    if host_keys is None:
        host_keys = ["ssh-ed25519", "rsa-sha2-256", "ecdsa-sha2-nistp256"]
    if macs is None:
        macs = ["hmac-sha2-256"]
    if compression is None:
        compression = ["none"]

    msg = bytes([20])            # SSH_MSG_KEXINIT
    msg += os.urandom(16)        # cookie
    msg += encode_name_list(kex)
    msg += encode_name_list(host_keys)
    msg += encode_name_list(ciphers_c2s)
    msg += encode_name_list(ciphers_s2c)
    msg += encode_name_list(macs)
    msg += encode_name_list(macs)
    msg += encode_name_list(compression)
    msg += encode_name_list(compression)
    msg += encode_name_list([])  # languages c2s
    msg += encode_name_list([])  # languages s2c
    msg += bytes([0])            # first_kex_packet_follows = false
    msg += struct.pack(">I", 0)  # reserved

    return msg


def frame_ssh_packet(payload):
    """Wrap a payload in SSH binary packet framing (unencrypted)."""
    # padding must be at least 4 bytes, total (4+1+payload+padding) multiple of 8
    block_size = 8
    min_pad = 4
    # packet_length = 1 (pad_len) + len(payload) + padding
    base = 1 + len(payload)
    pad_len = block_size - (base % block_size)
    if pad_len < min_pad:
        pad_len += block_size

    packet_length = base + pad_len
    return struct.pack(">I", packet_length) + bytes([pad_len]) + payload + os.urandom(pad_len)


def read_ssh_packet(sock):
    """Read one SSH binary packet, return the payload."""
    header = recv_exact(sock, 4)
    if not header:
        return None
    packet_length = struct.unpack(">I", header)[0]
    if packet_length > 256 * 1024:  # sanity
        return None
    rest = recv_exact(sock, packet_length)
    if not rest:
        return None
    pad_len = rest[0]
    payload = rest[1 : packet_length - pad_len]
    return payload


def recv_exact(sock, n):
    """Receive exactly n bytes."""
    buf = b""
    while len(buf) < n:
        chunk = sock.recv(n - len(buf))
        if not chunk:
            return None
        buf += chunk
    return buf


def parse_server_kexinit(payload):
    """Parse a KEXINIT payload and return dict of algorithm lists."""
    if not payload or payload[0] != 20:
        return None

    offset = 1 + 16  # skip type + cookie
    labels = [
        "kex", "host_keys",
        "enc_c2s", "enc_s2c",
        "mac_c2s", "mac_s2c",
        "comp_c2s", "comp_s2c",
        "lang_c2s", "lang_s2c",
    ]
    result = {}
    for label in labels:
        length = struct.unpack(">I", payload[offset:offset+4])[0]
        offset += 4
        names = payload[offset:offset+length].decode("ascii", errors="replace")
        offset += length
        result[label] = names.split(",") if names else []
    return result


def negotiate(client_list, server_list):
    """SSH algorithm negotiation: first client algorithm also in server list wins."""
    for algo in client_list:
        if algo in server_list:
            return algo
    return None


def test_cipher_set(host, port, label, ciphers, kex=None):
    """
    Connect, exchange banners, send KEXINIT with specified ciphers,
    read server KEXINIT, and check if negotiation would succeed.
    """
    print(f"\n  --- {label} ---")
    print(f"  Offering ciphers: {ciphers}")

    try:
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
        sock.sendall(b"SSH-2.0-CipherProbe\r\n")

        # Read server's KEXINIT
        server_kexinit_payload = read_ssh_packet(sock)
        if not server_kexinit_payload:
            print("  [!] Failed to read server KEXINIT")
            sock.close()
            return

        server_algos = parse_server_kexinit(server_kexinit_payload)
        if not server_algos:
            print("  [!] Failed to parse server KEXINIT")
            sock.close()
            return

        # Send our KEXINIT
        our_kexinit = build_kexinit(ciphers, kex=kex)
        sock.sendall(frame_ssh_packet(our_kexinit))

        # Check what would be negotiated
        agreed_enc = negotiate(ciphers, server_algos["enc_c2s"])
        agreed_kex = negotiate(
            kex or ["curve25519-sha256", "ecdh-sha2-nistp256", "diffie-hellman-group14-sha256"],
            server_algos["kex"]
        )

        if agreed_enc:
            print(f"  [!!] Server WOULD AGREE to cipher: {agreed_enc}")
            if agreed_enc == "none":
                print("  [VULNERABLE] Unencrypted SSH session possible!")
        else:
            print(f"  [OK] No cipher match — server would reject")
            print(f"       Server offers: {server_algos['enc_c2s']}")

        # Read server's response — it may send DISCONNECT if no algorithms match
        try:
            response = read_ssh_packet(sock)
            if response and response[0] == 1:  # SSH_MSG_DISCONNECT
                reason = struct.unpack(">I", response[1:5])[0] if len(response) >= 5 else 0
                desc_len = struct.unpack(">I", response[5:9])[0] if len(response) >= 9 else 0
                desc = response[9:9+desc_len].decode("utf-8", errors="replace") if desc_len else ""
                print(f"  Server DISCONNECT: reason={reason} desc=\"{desc}\"")
        except:
            pass

        sock.close()

    except Exception as e:
        print(f"  Error: {e}")


def main():
    if len(sys.argv) < 2:
        print(f"Usage: {sys.argv[0]} <host> [port]")
        sys.exit(1)

    host = sys.argv[1]
    port = int(sys.argv[2]) if len(sys.argv) > 2 else 22

    print("=" * 60)
    print("SSH Cipher Downgrade Test")
    print(f"Target: {host}:{port}")
    print("=" * 60)

    # Test 1: Only offer 'none' cipher
    test_cipher_set(host, port, "Test: 'none' cipher only", ["none"])

    # Test 2: Offer 'none' first, then real ciphers
    test_cipher_set(host, port, "Test: 'none' preferred, fallback to real",
                    ["none", "aes128-ctr", "aes256-ctr"])

    # Test 3: Only offer weak/deprecated ciphers
    test_cipher_set(host, port, "Test: weak ciphers only",
                    ["3des-cbc", "arcfour", "blowfish-cbc", "cast128-cbc"])

    # Test 4: Only offer CBC-mode ciphers
    test_cipher_set(host, port, "Test: CBC-mode ciphers only",
                    ["aes128-cbc", "aes192-cbc", "aes256-cbc"])

    # Test 5: Offer deprecated KEX + deprecated cipher
    test_cipher_set(host, port, "Test: SHA-1 KEX + weak ciphers",
                    ["3des-cbc", "aes128-cbc"],
                    kex=["diffie-hellman-group1-sha1",
                         "diffie-hellman-group-exchange-sha1"])

    print("\n" + "=" * 60)
    print("CIPHER DOWNGRADE TEST COMPLETE")
    print("=" * 60)


if __name__ == "__main__":
    main()
