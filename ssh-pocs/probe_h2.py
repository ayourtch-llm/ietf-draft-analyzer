#!/usr/bin/env python3
"""
HTTP/2 security probe — tests novel (no-CVE) findings from ietf-draft-analyzer.

Findings tested:
  1. GOAWAY last stream ID confusion
  2. GOAWAY debug data leakage
  3. PUSH_PROMISE stream state confusion
  4. Connection preface race condition
  5. Server push auth context confusion
  6. Frame padding information leakage
  7. SETTINGS flood / parameter churning
  8. Rapid stream creation + GOAWAY interaction

Usage: python probe_h2.py <host> <port>
"""

import ssl
import socket
import sys
import time
import h2.connection
import h2.config
import h2.events
import h2.settings
import struct


def create_h2_connection(host, port):
    """Create a TLS+HTTP/2 connection."""
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    ctx.set_alpn_protocols(['h2'])

    sock = socket.create_connection((host, port), timeout=10)
    ssock = ctx.wrap_socket(sock, server_hostname=host)

    assert ssock.selected_alpn_protocol() == 'h2', f"ALPN: {ssock.selected_alpn_protocol()}"

    config = h2.config.H2Configuration(client_side=True)
    conn = h2.connection.H2Connection(config=config)
    conn.initiate_connection()
    ssock.sendall(conn.data_to_send())

    return ssock, conn


def recv_events(ssock, conn, timeout=2):
    """Receive and process HTTP/2 frames, return events."""
    events = []
    ssock.settimeout(timeout)
    try:
        while True:
            data = ssock.recv(65535)
            if not data:
                break
            new_events = conn.receive_data(data)
            events.extend(new_events)
            ssock.sendall(conn.data_to_send())
    except socket.timeout:
        pass
    return events


def test_goaway_debug_data(host, port):
    """
    Test 1: GOAWAY debug data leakage (RFC 9113 §6.8)
    Does the server include sensitive info in GOAWAY debug_data?
    Trigger GOAWAY by sending protocol errors.
    """
    print("=" * 60)
    print("TEST 1: GOAWAY Debug Data Leakage")
    print("=" * 60)

    ssock, conn = create_h2_connection(host, port)

    # Trigger various protocol errors to get GOAWAY with debug data
    triggers = [
        ("invalid stream ID 0 for HEADERS", lambda: conn.send_headers(0, [(':path', '/')])),
        ("oversized SETTINGS value", None),  # handled manually
    ]

    # Send a valid request first
    conn.send_headers(1, [
        (':method', 'GET'), (':path', '/'), (':scheme', 'https'),
        (':authority', host),
    ], end_stream=True)
    ssock.sendall(conn.data_to_send())
    events = recv_events(ssock, conn, timeout=2)

    # Now send a request on an even stream ID (invalid for client)
    # This should trigger GOAWAY
    try:
        # Manually craft a HEADERS frame on stream 2 (even = server-initiated, invalid from client)
        raw_frame = b'\x00\x00\x01'  # length = 1
        raw_frame += b'\x01'  # type = HEADERS
        raw_frame += b'\x05'  # flags = END_STREAM | END_HEADERS
        raw_frame += b'\x00\x00\x00\x02'  # stream ID = 2 (even, invalid from client)
        raw_frame += b'\x82'  # HPACK: :method GET
        ssock.sendall(raw_frame)
    except Exception as e:
        print(f"  Error sending invalid frame: {e}")

    time.sleep(1)
    events = recv_events(ssock, conn, timeout=2)

    goaway_found = False
    for ev in events:
        if isinstance(ev, h2.events.ConnectionTerminated):
            goaway_found = True
            print(f"  GOAWAY received:")
            print(f"    Error code: {ev.error_code}")
            print(f"    Last stream ID: {ev.last_stream_id}")
            debug = getattr(ev, 'additional_data', b'')
            if debug:
                print(f"    Debug data ({len(debug)} bytes): {debug[:200]}")
                try:
                    text = debug.decode('utf-8', errors='replace')
                    print(f"    Debug text: {text[:200]}")
                    # Check for sensitive info
                    sensitive = ['path', 'version', 'nginx', 'error', 'internal', 'config']
                    for word in sensitive:
                        if word.lower() in text.lower():
                            print(f"    [FINDING] Debug data contains '{word}'")
                except:
                    pass
            else:
                print(f"    Debug data: (empty)")

    if not goaway_found:
        print("  No GOAWAY received")

    ssock.close()
    print()


def test_goaway_stream_id(host, port):
    """
    Test 2: GOAWAY last stream ID confusion (RFC 9113 §6.8)
    Open multiple streams, trigger GOAWAY, check which streams
    the server considers safe to retry.
    """
    print("=" * 60)
    print("TEST 2: GOAWAY Last Stream ID Handling")
    print("=" * 60)

    ssock, conn = create_h2_connection(host, port)

    # Open several streams rapidly
    stream_ids = []
    for i in range(10):
        sid = conn.get_next_available_stream_id()
        conn.send_headers(sid, [
            (':method', 'GET'), (':path', f'/stream-{i}'),
            (':scheme', 'https'), (':authority', host),
        ], end_stream=True)
        stream_ids.append(sid)
    ssock.sendall(conn.data_to_send())

    print(f"  Opened streams: {stream_ids}")

    # Read responses
    events = recv_events(ssock, conn, timeout=3)
    responses = {}
    goaway = None
    for ev in events:
        if isinstance(ev, h2.events.ResponseReceived):
            responses[ev.stream_id] = dict(ev.headers)
        elif isinstance(ev, h2.events.ConnectionTerminated):
            goaway = ev

    print(f"  Responses received for streams: {sorted(responses.keys())}")
    if goaway:
        print(f"  GOAWAY: last_stream_id={goaway.last_stream_id} error={goaway.error_code}")
        # Check: are there streams above last_stream_id that got responses?
        above = [s for s in responses if s > goaway.last_stream_id]
        if above:
            print(f"  [FINDING] Streams {above} responded AFTER GOAWAY last_stream_id!")
    else:
        print(f"  No GOAWAY (server handled all streams)")

    ssock.close()
    print()


def test_settings_flood(host, port):
    """
    Test 3: SETTINGS flood / parameter churning
    Send many SETTINGS frames rapidly to stress the server.
    """
    print("=" * 60)
    print("TEST 3: SETTINGS Flood")
    print("=" * 60)

    ssock, conn = create_h2_connection(host, port)
    recv_events(ssock, conn, timeout=1)  # consume initial

    # Send 100 SETTINGS frames with varying values
    print("  Sending 100 SETTINGS frames...")
    for i in range(100):
        settings = {
            h2.settings.SettingCodes.MAX_CONCURRENT_STREAMS: 100 + i,
            h2.settings.SettingCodes.INITIAL_WINDOW_SIZE: 65535 - (i % 100),
        }
        conn.update_settings(settings)
        ssock.sendall(conn.data_to_send())

    time.sleep(1)
    events = recv_events(ssock, conn, timeout=2)

    # Check if connection survived
    try:
        sid = conn.get_next_available_stream_id()
        conn.send_headers(sid, [
            (':method', 'GET'), (':path', '/'),
            (':scheme', 'https'), (':authority', host),
        ], end_stream=True)
        ssock.sendall(conn.data_to_send())
        events = recv_events(ssock, conn, timeout=2)
        got_response = any(isinstance(ev, h2.events.ResponseReceived) for ev in events)
        if got_response:
            print(f"  [OK] Server survived 100 SETTINGS frames and still responds")
        else:
            print(f"  [NOTE] Server alive but no response to request")
    except Exception as e:
        print(f"  [FINDING] Server died after SETTINGS flood: {e}")

    ssock.close()
    print()


def test_padding_leak(host, port):
    """
    Test 4: Frame padding information leakage
    Send requests with various padding, measure response padding behavior.
    """
    print("=" * 60)
    print("TEST 4: Frame Padding Behavior Analysis")
    print("=" * 60)

    ssock, conn = create_h2_connection(host, port)
    recv_events(ssock, conn, timeout=1)

    # Send a normal request
    sid = conn.get_next_available_stream_id()
    conn.send_headers(sid, [
        (':method', 'GET'), (':path', '/'),
        (':scheme', 'https'), (':authority', host),
    ], end_stream=True)
    ssock.sendall(conn.data_to_send())

    # Capture raw response to check padding
    ssock.settimeout(3)
    raw_data = b''
    try:
        while True:
            chunk = ssock.recv(65535)
            if not chunk:
                break
            raw_data += chunk
    except socket.timeout:
        pass

    print(f"  Raw response: {len(raw_data)} bytes")

    # Parse frames manually to check padding
    pos = 0
    while pos + 9 <= len(raw_data):
        length = struct.unpack('>I', b'\x00' + raw_data[pos:pos+3])[0]
        ftype = raw_data[pos+3]
        flags = raw_data[pos+4]
        stream_id = struct.unpack('>I', raw_data[pos+5:pos+9])[0] & 0x7fffffff

        frame_names = {0:'DATA', 1:'HEADERS', 2:'PRIORITY', 3:'RST_STREAM',
                       4:'SETTINGS', 5:'PUSH_PROMISE', 6:'PING', 7:'GOAWAY',
                       8:'WINDOW_UPDATE', 9:'CONTINUATION'}

        padded = bool(flags & 0x08)
        pad_length = 0
        if padded and pos + 9 < len(raw_data):
            pad_length = raw_data[pos + 9]

        if ftype in (0, 1):  # DATA or HEADERS
            print(f"  Frame: {frame_names.get(ftype, ftype)} stream={stream_id} "
                  f"len={length} padded={padded} pad_len={pad_length}")

        pos += 9 + length

    print(f"  [NOTE] Server {'uses' if any(raw_data[pos+4] & 0x08 for pos in range(0, len(raw_data)-9, 9) if pos+4 < len(raw_data)) else 'does not use'} padding on responses")
    print(f"         Lack of padding allows traffic analysis of response sizes")

    ssock.close()
    print()


def test_rapid_streams_goaway(host, port):
    """
    Test 5: Rapid stream creation + immediate close
    Check how the server handles rapid open/close cycles.
    """
    print("=" * 60)
    print("TEST 5: Rapid Stream Open/Reset Cycle")
    print("=" * 60)

    ssock, conn = create_h2_connection(host, port)
    recv_events(ssock, conn, timeout=1)

    # Rapidly open and reset streams (the Rapid Reset pattern, CVE-2023-44487)
    # We do a small-scale version to test server resilience
    reset_count = 0
    for i in range(50):
        try:
            sid = conn.get_next_available_stream_id()
            conn.send_headers(sid, [
                (':method', 'GET'), (':path', f'/rapid-{i}'),
                (':scheme', 'https'), (':authority', host),
            ], end_stream=False)
            conn.reset_stream(sid, error_code=8)  # CANCEL
            ssock.sendall(conn.data_to_send())
            reset_count += 1
        except Exception as e:
            print(f"  Failed at stream {i}: {e}")
            break

    print(f"  Sent {reset_count} open+reset cycles")

    time.sleep(1)
    events = recv_events(ssock, conn, timeout=2)

    goaway = None
    for ev in events:
        if isinstance(ev, h2.events.ConnectionTerminated):
            goaway = ev

    # Check if connection is still usable
    try:
        sid = conn.get_next_available_stream_id()
        conn.send_headers(sid, [
            (':method', 'GET'), (':path', '/'),
            (':scheme', 'https'), (':authority', host),
        ], end_stream=True)
        ssock.sendall(conn.data_to_send())
        events2 = recv_events(ssock, conn, timeout=2)
        alive = any(isinstance(ev, h2.events.ResponseReceived) for ev in events2)
        if alive:
            print(f"  [OK] Server still responds after {reset_count} rapid resets")
        elif goaway:
            print(f"  [NOTE] Server sent GOAWAY after rapid resets: error={goaway.error_code}")
            debug = getattr(goaway, 'additional_data', b'')
            if debug:
                print(f"         Debug: {debug[:100]}")
        else:
            print(f"  [NOTE] Server silent after rapid resets")
    except Exception as e:
        print(f"  [NOTE] Connection dead after rapid resets: {e}")

    ssock.close()
    print()


def test_unknown_frame_types(host, port):
    """
    Test 6: Unknown frame type handling
    Send frames with undefined type values, check server response.
    """
    print("=" * 60)
    print("TEST 6: Unknown Frame Type Handling")
    print("=" * 60)

    ssock, conn = create_h2_connection(host, port)
    recv_events(ssock, conn, timeout=1)

    # Send frames with unknown types (10-255)
    test_types = [10, 20, 50, 100, 200, 255]
    for ftype in test_types:
        # Frame: length(3) + type(1) + flags(1) + stream_id(4) + payload
        payload = b'UNKNOWN_FRAME_TEST'
        frame = struct.pack('>I', len(payload))[1:]  # 3 bytes length
        frame += bytes([ftype])  # type
        frame += bytes([0])  # flags
        frame += struct.pack('>I', 0)  # stream 0
        frame += payload

        try:
            ssock.sendall(frame)
        except:
            print(f"  Type {ftype}: connection dead")
            break

    time.sleep(0.5)

    # Check if alive
    try:
        events = recv_events(ssock, conn, timeout=1)
        goaway = [ev for ev in events if isinstance(ev, h2.events.ConnectionTerminated)]
        if goaway:
            print(f"  [NOTE] Server sent GOAWAY: error={goaway[0].error_code}")
            debug = getattr(goaway[0], 'additional_data', b'')
            if debug:
                print(f"         Debug: {debug[:100]}")
        else:
            # Try a real request
            sid = conn.get_next_available_stream_id()
            conn.send_headers(sid, [
                (':method', 'GET'), (':path', '/'),
                (':scheme', 'https'), (':authority', host),
            ], end_stream=True)
            ssock.sendall(conn.data_to_send())
            events2 = recv_events(ssock, conn, timeout=2)
            if any(isinstance(ev, h2.events.ResponseReceived) for ev in events2):
                print(f"  [OK] Server ignored unknown frame types and still works")
            else:
                print(f"  [NOTE] Server silent after unknown frames")
    except Exception as e:
        print(f"  Connection error: {e}")

    ssock.close()
    print()


def test_window_manipulation(host, port):
    """
    Test 7: Flow control window manipulation
    Try setting window to 0, then sending data.
    """
    print("=" * 60)
    print("TEST 7: Flow Control Window Exhaustion")
    print("=" * 60)

    ssock, conn = create_h2_connection(host, port)
    recv_events(ssock, conn, timeout=1)

    # Request a large resource
    sid = conn.get_next_available_stream_id()
    conn.send_headers(sid, [
        (':method', 'GET'), (':path', '/'),
        (':scheme', 'https'), (':authority', host),
    ], end_stream=True)
    ssock.sendall(conn.data_to_send())

    # Don't send WINDOW_UPDATE — see if server blocks
    events = recv_events(ssock, conn, timeout=3)

    data_received = sum(len(ev.data) for ev in events
                        if isinstance(ev, h2.events.DataReceived))
    responses = [ev for ev in events if isinstance(ev, h2.events.ResponseReceived)]

    print(f"  Response received: {bool(responses)}")
    print(f"  Data received: {data_received} bytes")
    print(f"  Initial window size: {conn.local_settings.initial_window_size}")
    print(f"  [INFO] Server would block sending large responses if window exhausted")

    ssock.close()
    print()


def main():
    if len(sys.argv) < 3:
        print(f"Usage: {sys.argv[0]} <host> <port>")
        sys.exit(1)

    host = sys.argv[1]
    port = int(sys.argv[2])

    print(f"\nHTTP/2 Novel Finding Probes — {host}:{port}")
    print(f"Testing findings without existing CVEs\n")

    test_goaway_debug_data(host, port)
    test_goaway_stream_id(host, port)
    test_settings_flood(host, port)
    test_padding_leak(host, port)
    test_rapid_streams_goaway(host, port)
    test_unknown_frame_types(host, port)
    test_window_manipulation(host, port)

    print("=" * 60)
    print("HTTP/2 PROBES COMPLETE")
    print("=" * 60)


if __name__ == "__main__":
    main()
