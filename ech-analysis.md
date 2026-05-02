# Security Analysis: TLS Encrypted Client Hello (ECH)

**Source:** draft-ietf-tls-esni-22
**Generated:** 2026-05-02T17:08:49.478442+00:00
**Model:** Qwen3.6-27B-Q4_K_M.gguf
**Duration:** 565s
**State machines extracted:** 10
**Security leads:** 29

## Category Breakdown

| Category | Count |
|----------|-------|
| ImplementationAmbiguity | 5 |
| DenialOfService | 4 |
| OversizedPayload | 4 |
| MissingValidation | 4 |
| RaceCondition | 4 |
| StateConfusion | 3 |
| AuthBypass | 3 |
| ReplayAttack | 2 |

## Severity Breakdown

| Severity | Count |
|----------|-------|
| high | 9 |
| medium | 13 |
| low | 7 |

## Findings

### 1. Trial Decryption DoS via Ignored Configuration Identifiers

- **Category:** DenialOfService
- **Severity:** high
- **Confidence:** 0.95
- **Prerequisites:** Server is configured to ignore config_id (e.g., local discovery mode), Server supports multiple ECHConfig candidates
- **Entities:** client-facing server, attacker

**Description:**

Step 1: Attacker sends a high volume of ClientHello messages with randomly generated or invalid config_id values. Step 2: The server, configured to ignore configuration identifiers (e.g., for local discovery mode), cannot filter keys based on config_id. Step 3: The server performs trial decryption for every known ECHConfig candidate for each incoming message. Step 4: This forces the server to perform computationally expensive HPKE decryption operations for every packet, exhausting CPU resources and causing a Denial of Service.

**RFC References:**

- Section ignored-configs: "As a result, ignoring configuration identifiers may exacerbate DoS attacks. Specifically, an adversary may send malicious ClientHello messages, i.e., those which will not decrypt with any known ECH key, in order to force wasteful decryption. Servers that support this feature should, for example, implement some form of rate limiting mechanism to limit the potential damage caused by such attacks."

**Mitigation:** Implement rate limiting mechanisms on incoming ECH connections. Avoid ignoring configuration identifiers unless strictly necessary. Use config_id to quickly filter and select the correct ECHConfig, reducing the number of trial decryptions.

---

### 2. ClientHelloInner Decompression Amplification

- **Category:** OversizedPayload
- **Severity:** high
- **Confidence:** 0.95
- **Prerequisites:** Attacker can send crafted ClientHelloOuter, Server supports ech_outer_extensions compression
- **Entities:** client, client-facing server, backend server

**Description:**

Step 1: An attacker crafts a ClientHelloOuter containing a large extension of length L. Step 2: The attacker includes an 'ech_outer_extensions' extension in the EncodedClientHelloInner that references the large extension N times. Step 3: The client-facing server decompresses the ClientHelloInner, copying the large extension N times, resulting in O(N*L) memory usage and potential packet amplification to the backend server in Split Mode.

**RFC References:**

- Section decompression-amp: "If the same ClientHelloOuter extension can be copied multiple times, an attacker could cause the client-facing server to construct a large ClientHelloInner by including a large extension in ClientHelloOuter, of length L, and an OuterExtensions list referencing N copies of that extension. The client-facing server would then use O(N*L) memory in response to O(N+L) bandwidth from the client."
- Section encoding-inner: "These requirements prevent an attacker from performing a packet amplification attack, by crafting a ClientHelloOuter which decompresses to a much larger ClientHelloInner."

**Mitigation:** The RFC mandates that OuterExtensions must be referenced in order, duplicate references must be rejected, and implementations SHOULD process extensions in linear time. Servers must abort with 'illegal_parameter' if any extension is referenced more than once or if extensions are not in the same order.

---

### 3. ClientHelloInner Decompression Amplification via OuterExtensions

- **Category:** StateConfusion
- **Severity:** high
- **Confidence:** 0.90
- **Prerequisites:** attacker can craft ClientHelloOuter, server supports ech_outer_extensions
- **Entities:** client, client-facing server, backend server

**Description:**

Step 1: An attacker crafts a ClientHelloOuter with a large extension and an 'ech_outer_extensions' extension in the ClientHelloInner that references the large extension multiple times. Step 2: The client-facing server decompresses the ClientHelloInner, copying the large extension multiple times into memory. Step 3: The server forwards the decompressed ClientHelloInner to the backend server, causing an amplification of bandwidth and memory usage. Step 4: The backend server processes the large ClientHelloInner, potentially leading to a denial of service.

**RFC References:**

- Section encoding-inner: "The client-facing server computes ClientHelloInner by reversing this process... It then looks for an 'ech_outer_extensions' extension. If found, it replaces the extension with the corresponding sequence of extensions in the ClientHelloOuter."
- Section decompression-amp: "If the same ClientHelloOuter extension can be copied multiple times, an attacker could cause the client-facing server to construct a large ClientHelloInner by including a large extension in ClientHelloOuter, of length L, and an OuterExtensions list referencing N copies of that extension."

**Mitigation:** Implement strict limits on the size of decompressed ClientHelloInner and the number of references in OuterExtensions. Use linear-time decompression algorithms and reject duplicate references to the same extension.

---

### 4. Trial Decryption DoS via Ignored Configuration Identifiers

- **Category:** MissingValidation
- **Severity:** high
- **Confidence:** 0.90
- **Prerequisites:** attacker can send packets to the client-facing server, server supports trial decryption mode or ignores config_ids
- **Entities:** client-facing server, attacker

**Description:**

Step 1: The attacker sends a ClientHello with a randomly generated or invalid config_id in the ECHClientHello extension. Step 2: The client-facing server, unable to match the config_id to a known ECHConfig, is forced to perform trial decryption using all known ECHConfig private keys. Step 3: This computationally expensive process is repeated for each malicious packet, exhausting server resources and causing a Denial of Service (DoS). The protocol lacks a mandatory validation or rate-limiting mechanism for unrecognized config_ids, explicitly noting that 'ignoring configuration identifiers may exacerbate DoS attacks.'

**RFC References:**

- Section ignored-configs: "Ignoring configuration identifiers may be useful in scenarios where clients and client-facing servers do not want to reveal information... As a result, ignoring configuration identifiers may exacerbate DoS attacks. Specifically, an adversary may send malicious ClientHello messages, i.e., those which will not decrypt with any known ECH key, in order to force wasteful decryption."
- Section client-facing-server: "Collect all known ECHConfig values as candidates, with trial decryption below determining the final selection."

**Mitigation:** Implement rate limiting for connections that fail ECH decryption. Use distinct config_ids to avoid trial decryption. Validate config_id against a known set before attempting decryption.

---

### 5. ClientHelloInner Decompression Amplification

- **Category:** DenialOfService
- **Severity:** high
- **Confidence:** 0.90
- **Prerequisites:** Server implementation does not enforce linear-time decompression, Server allows duplicate references in OuterExtensions
- **Entities:** client-facing server, backend server, attacker

**Description:**

Step 1: Attacker crafts a ClientHelloOuter containing a large extension (length L) and an OuterExtensions list referencing this extension N times. Step 2: The client-facing server processes the EncodedClientHelloInner and attempts to decompress it by copying the large extension N times. Step 3: The server consumes O(N*L) memory and CPU time to construct the ClientHelloInner. Step 4: In Split Mode, the server transmits this O(N*L) sized packet to the backend server, amplifying the traffic and exhausting server resources.

**RFC References:**

- Section decompression-amp: "If the same ClientHelloOuter extension can be copied multiple times, an attacker could cause the client-facing server to construct a large ClientHelloInner by including a large extension in ClientHelloOuter, of length L, and an OuterExtensions list referencing N copies of that extension. The client-facing server would then use O(N*L) memory in response to O(N+L) bandwidth from the client."
- Section encoding-inner: "These requirements prevent an attacker from performing a packet amplification attack, by crafting a ClientHelloOuter which decompresses to a much larger ClientHelloInner."

**Mitigation:** Enforce that OuterExtensions references are unique and ordered. Implement linear-time decompression algorithms. Reject duplicate extension references in OuterExtensions. Limit the maximum size of the decompressed ClientHelloInner.

---

### 6. Packet Amplification via OuterExtensions Decompression

- **Category:** MissingValidation
- **Severity:** high
- **Confidence:** 0.85
- **Prerequisites:** attacker can send crafted ClientHelloOuter, server implementation fails to enforce linear-time processing or total size limits
- **Entities:** client-facing server, attacker

**Description:**

Step 1: The attacker crafts a ClientHelloOuter containing a large extension (length L). Step 2: The attacker includes an 'ech_outer_extensions' extension in the EncodedClientHelloInner that references the large extension N times. Step 3: The client-facing server decompresses the ClientHelloInner, copying the large extension N times, resulting in an O(N*L) memory usage and packet size amplification. While the RFC mandates rejecting duplicate references, naive implementations or those failing to validate the total decompressed size against limits can be exploited for resource exhaustion or amplification attacks.

**RFC References:**

- Section decompression-amp: "If the same ClientHelloOuter extension can be copied multiple times, an attacker could cause the client-facing server to construct a large ClientHelloInner by including a large extension in ClientHelloOuter, of length L, and an OuterExtensions list referencing N copies of that extension. The client-facing server would then use O(N*L) memory in response to O(N+L) bandwidth from the client."
- Section encoding-inner: "The server MUST abort the connection with an 'illegal_parameter' alert if any of the following are true: Any extension is referenced in OuterExtensions more than once."

**Mitigation:** Enforce strict limits on the total size of the decompressed ClientHelloInner. Implement linear-time decompression algorithms as recommended. Validate that OuterExtensions do not cause excessive memory allocation.

---

### 7. State Management Ambiguity in HelloRetryRequest Processing

- **Category:** ImplementationAmbiguity
- **Severity:** high
- **Confidence:** 0.85
- **Prerequisites:** Server sends HelloRetryRequest, Server state is lost or corrupted, Client sends second ClientHelloOuter
- **Entities:** client, client-facing server

**Description:**

Step 1: The client sends a ClientHelloOuter with ECH. Step 2: The server responds with a HelloRetryRequest (HRR). Step 3: The RFC states that the client-facing server does not repeat the ECHConfig selection steps with the second ClientHelloOuter but continues with the selection from the first. However, it also requires checking that ECHClientHello.cipher_suite and config_id are unchanged. This creates an ambiguity in state management: if the server's state is lost or corrupted between the first and second ClientHello, it may incorrectly reject a valid second ClientHello or fail to decrypt it, leading to a handshake failure. Additionally, the requirement to reuse the HPKE context without explicitly defining how to handle sequence number resets could lead to nonce reuse vulnerabilities if not implemented carefully.

**RFC References:**

- Section client-facing-server-hrr: "After sending or forwarding a HelloRetryRequest, the client-facing server does not repeat the steps in with the second ClientHelloOuter. Instead, it continues with the ECHConfig selection from the first ClientHelloOuter as follows: ... Otherwise, it checks that ECHClientHello.cipher_suite and ECHClientHello.config_id are unchanged, and that ECHClientHello.enc is empty. If not, it MUST abort the handshake with an 'illegal_parameter' alert."
- Section accepted-ech: "It reuses the original HPKE encryption context computed in and uses the empty string for . The HPKE context maintains a sequence number, so this operation internally uses a fresh nonce for each AEAD operation."

**Mitigation:** Implementations should maintain robust state management for ECH handshakes, ensuring that the HPKE context and ECHConfig selection state are preserved across HelloRetryRequest exchanges. Clear error handling should be implemented for state loss scenarios.

---

### 8. HelloRetryRequest Hijack via State Race

- **Category:** RaceCondition
- **Severity:** high
- **Confidence:** 0.85
- **Prerequisites:** attacker is on-path, server maintains HRR state, attacker can generate valid ClientHello quickly
- **Entities:** client, server, attacker

**Description:**

Step 1: Attacker intercepts a legitimate ClientHello with an 'encrypted_client_hello' extension and forwards it to the server. Step 2: Server triggers a HelloRetryRequest (HRR) based on the legitimate ClientHello. Step 3: Attacker races to generate and send its own ClientHello in response to the HRR before the legitimate client can, exploiting server state management to potentially leak information about the legitimate ClientHelloInner (e.g., SNI) by observing server behavior or certificate encryption keys.

**RFC References:**

- Section flow-hrr-hijack: "This attack aims to exploit server HRR state management to recover information about a legitimate ClientHello using its own attacker-controlled ClientHello. To begin, the attacker intercepts and forwards a legitimate ClientHello with an 'encrypted_client_hello' (ech) extension to the server, which triggers a legitimate HelloRetryRequest in return. Rather than forward the retry to the client, the attacker attempts to generate its own ClientHello in response based on the contents of the first ClientHello and HelloRetryRequest exchange with the result that the server encrypts the Certificate to the attacker."

**Mitigation:** Use the same HPKE context for both ClientHello messages. The attacker does not possess the context's keys, so it cannot generate a valid encryption of the second inner ClientHello.

---

### 9. Split Mode Backend Server Authentication Bypass via Correlation

- **Category:** AuthBypass
- **Severity:** high
- **Confidence:** 0.75
- **Prerequisites:** Attacker is on-path between client and client-facing server, Attacker can correlate traffic between client-facing server and backend server, Split Mode deployment
- **Entities:** client, client-facing server, backend server

**Description:**

Step 1: In Split Mode, the client-facing server and backend server are separate entities. Step 2: The protocol assumes that the channel between the client-facing server and the backend server is authenticated. Step 3: If an attacker can correlate messages between the client and the client-facing server with messages between the client-facing server and the backend server, they can potentially link information unique to the backend server (e.g., server name, IP address) with the client's encrypted ClientHelloInner. Step 4: This correlation could allow the attacker to bypass the anonymity set and potentially target specific backend servers, undermining the authentication and privacy guarantees of ECH. Step 5: If the attacker can also manipulate the client-facing server, they could potentially inject or modify messages to the backend server, leading to a full authentication bypass.

**RFC References:**

- Section goals: "The attacker cannot correlate messages between client and client-facing server with messages between client-facing and backend server. Such correlation could allow an attacker to link information unique to a backend server, such as their server name or IP address, with a client's encrypted ClientHelloInner."

**Mitigation:** Implement strict anti-correlation measures between the client-facing server and the backend server. Use techniques such as traffic padding, timing randomization, and separate network paths to prevent an attacker from linking the two sides of the connection. Ensure that the authenticated channel between the client-facing server and the backend server is robust and cannot be compromised.

---

### 10. Quadratic Time Decompression DoS

- **Category:** OversizedPayload
- **Severity:** medium
- **Confidence:** 0.90
- **Prerequisites:** Attacker can send crafted ClientHelloOuter, Server implementation uses naive extension lookup
- **Entities:** client, client-facing server

**Description:**

Step 1: An attacker sends a ClientHelloOuter with M extensions. Step 2: The attacker crafts an EncodedClientHelloInner with N references in OuterExtensions. Step 3: If the server uses a naive O(M) lookup for each of the N references, the total processing time becomes O(M*N), leading to CPU exhaustion and denial of service.

**RFC References:**

- Section decompression-amp: "If looking up a ClientHelloOuter extension takes time linear in the number of extensions, the overall decoding process would take O(M*N) time, where M is the number of extensions in ClientHelloOuter and N is the size of OuterExtensions."
- Section encoding-inner: "Implementations SHOULD construct the ClientHelloInner in linear time. Quadratic time implementations (such as may happen via naive copying) create a denial of service risk."

**Mitigation:** Implementations MUST use a linear-time procedure for decompression, such as the one specified in Section 'linear-outer-extensions', which iterates through ClientHelloOuter extensions once while processing OuterExtensions.

---

### 11. SNI-Based Decryption DoS

- **Category:** DenialOfService
- **Severity:** medium
- **Confidence:** 0.85
- **Prerequisites:** Attacker can open multiple valid transport connections, Server resources are limited by decryption throughput
- **Entities:** client-facing server, attacker

**Description:**

Step 1: Attacker opens multiple valid transport connections to the server. Step 2: For each connection, the attacker sends a ClientHello with a valid ECHClientHello extension containing a valid digest but potentially malicious or high-cost inner content. Step 3: The server is required to decrypt these messages to process the handshake. Step 4: The volume of valid connections forces the server to perform continuous decryption operations, consuming CPU resources.

**RFC References:**

- Section prevent-sni-based-denial-of-service-attacks: "This design requires servers to decrypt ClientHello messages with ECHClientHello extensions carrying valid digests. Thus, it is possible for an attacker to force decryption operations on the server. This attack is bound by the number of valid transport connections an attacker can open."

**Mitigation:** Implement connection rate limiting. Use hardware acceleration for decryption. Monitor and throttle clients that initiate excessive handshakes.

---

### 12. ECH Rejection and Public Name Authentication Bypass

- **Category:** AuthBypass
- **Severity:** medium
- **Confidence:** 0.85
- **Prerequisites:** Attacker controls or can manipulate the client-facing server, Attacker can manipulate ECHConfig to point to a public name they control
- **Entities:** client, client-facing server, backend server

**Description:**

Step 1: The client initiates a connection with an ECH extension. Step 2: The server rejects ECH and proceeds with the handshake using the plaintext 'server_name' extension. Step 3: The client authenticates the connection with the public name (ECHConfig.contents.public_name) instead of the actual backend server's identity. Step 4: If the attacker controls the client-facing server or can manipulate the ECHConfig, they can present a certificate valid for the public name but not the actual backend server, effectively bypassing the backend server's authentication. Step 5: The client reports the connection as failed to the application but may still be used to trigger retries or leak information, potentially leading to a bypass if the application logic incorrectly handles the 'ech_required' alert or retry mechanism.

**RFC References:**

- Section auth-public-name: "When the server rejects ECH, it continues with the handshake using the plaintext 'server_name' extension instead... The client MUST verify that the certificate is valid for ECHConfig.contents.public_name... Note that authenticating a connection for the public name does not authenticate it for the origin. The TLS implementation MUST NOT report such connections as successful to the application."

**Mitigation:** Ensure that the application strictly enforces the 'ech_required' alert and does not proceed with any data exchange or state updates based on a connection that was authenticated only to the public name. Implement strict validation of ECHConfig sources and ensure that the public name cannot be trivially manipulated by an attacker.

---

### 13. Ambiguous ECHConfig Matching in Split Mode

- **Category:** ImplementationAmbiguity
- **Severity:** medium
- **Confidence:** 0.85
- **Prerequisites:** Client uses local discovery mode with randomized config_id, Server implementation defaults to config_id matching instead of trial decryption
- **Entities:** client, client-facing server

**Description:**

Step 1: The client sends a ClientHelloOuter with an 'encrypted_client_hello' extension containing a randomized config_id (local discovery mode). Step 2: The client-facing server receives the message and must select candidate ECHConfig values. The RFC states it can either match config_id or collect all known ECHConfigs for trial decryption. Step 3: The RFC mandates using the first method (config_id matching) unless specified by the application profile or externally configured, but also states that for local discovery mode, the second method SHOULD be used. This creates an ambiguity where different implementations may default to different matching strategies, potentially causing interoperability failures or allowing an attacker to force trial decryption DoS if the server incorrectly defaults to the first method when randomized config_ids are used.

**RFC References:**

- Section client-facing-server: "Some uses of ECH, such as local discovery mode, may randomize the ECHClientHello.config_id since it can be used as a tracking vector. In such cases, the second method SHOULD be used for matching the ECHClientHello to a known ECHConfig. ... Unless specified by the application profile or otherwise externally configured, implementations MUST use the first method."

**Mitigation:** Implementations should explicitly configure the ECHConfig matching strategy based on the deployment mode. For local discovery mode, ensure trial decryption is enabled by default or provide a clear configuration flag to override the mandatory first method.

---

### 14. Trial Decryption DoS via Ignored Config IDs

- **Category:** OversizedPayload
- **Severity:** medium
- **Confidence:** 0.85
- **Prerequisites:** Server supports ignoring configuration identifiers, Attacker can send high volume of connections
- **Entities:** client, client-facing server

**Description:**

Step 1: An attacker sends multiple malicious ClientHello messages with invalid or random ECHClientHello.payload values. Step 2: The attacker sets a random config_id, forcing the server to ignore the identifier. Step 3: The server performs trial decryption with every known ECH key for each message, wasting CPU resources and potentially leading to denial of service.

**RFC References:**

- Section ignored-configs: "Ignoring configuration identifiers may exacerbate DoS attacks. Specifically, an adversary may send malicious ClientHello messages, i.e., those which will not decrypt with any known ECH key, in order to force wasteful decryption."
- Section client-facing-server: "The server then iterates over the candidate ECHConfig values, attempting to decrypt the 'encrypted_client_hello' extension as follows."

**Mitigation:** Servers SHOULD implement rate limiting mechanisms. Implementations MUST NOT use the ignore-config-ids mode unless specified by the application profile or externally configured.

---

### 15. ECH HelloRetryRequest Replay

- **Category:** ReplayAttack
- **Severity:** medium
- **Confidence:** 0.80
- **Prerequisites:** attacker is on-path, attacker can capture HRR messages, client does not strictly bind HRR to the initial ClientHello transcript
- **Entities:** client, backend server, client-facing server

**Description:**

Step 1: Attacker captures a legitimate HelloRetryRequest (HRR) from a backend server, which contains an 'encrypted_client_hello' extension with an 8-byte confirmation signal derived from the transcript hash. Step 2: Attacker replays this HRR to a different client or the same client in a new connection attempt, potentially causing the client to incorrectly compute the second ClientHelloInner or accept a forged ECH acceptance signal. Step 3: The client processes the replayed HRR, computes the second ClientHelloOuter using the replayed confirmation, and sends it to the server, potentially leading to handshake confusion or state desynchronization if the server's backend does not match the replayed context.

**RFC References:**

- Section backend-server-hrr: "When the backend server sends HelloRetryRequest in response to the ClientHello, it similarly confirms ECH acceptance by adding a confirmation signal to its HelloRetryRequest... it sends the signal in an extension."
- Section client-facing-server-hrr: "If the client-facing server accepted ECH, it checks the second ClientHelloOuter also contains the 'encrypted_client_hello' extension... Finally, it decrypts the new ECHClientHello.payload as a second message with the previous HPKE context"

**Mitigation:** Ensure the HRR confirmation signal is tightly bound to the specific ClientHelloInner transcript hash and that the server validates the second ClientHelloInner against the original HRR context. TLS 1.3 random values and handshake hashes provide baseline protection, but ECH-specific replay of the confirmation extension must be mitigated by verifying the transcript_ech_conf matches the current handshake state.

---

### 16. Public Name Validation Bypass via IPv4 Literal Interpretation

- **Category:** MissingValidation
- **Severity:** medium
- **Confidence:** 0.80
- **Prerequisites:** attacker controls or influences ECHConfig distribution, client implementation has loose DNS name parsing
- **Entities:** client, attacker

**Description:**

Step 1: The attacker or misconfigured server provides an ECHConfig with a public_name that resembles an IPv4 address (e.g., '192.168.1.1' or '0xC0A80101'). Step 2: The client parses the public_name. If the client implementation incorrectly interprets the DNS name as an IP address due to missing validation of the LDH label structure or hexadecimal prefixes, it may connect to an unintended host or fail to properly authenticate the server. Step 3: The RFC mandates clients to ignore names that look like IPv4 literals, but failure to implement this validation strictly can lead to connection misdirection or privacy leaks.

**RFC References:**

- Section ech-configuration: "Clients additionally SHOULD ignore the structure if the final LDH label either consists of all ASCII digits... or is '0x' or '0X' followed by some, possibly empty, sequence of ASCII hexadecimal digits... This avoids public_name values that may be interpreted as IPv4 literals."
- Section auth-public-name: "Clients that incorporate DNS names and IP addresses into the same syntax... MUST reject names that would be interpreted as IPv4 addresses."

**Mitigation:** Strictly validate public_name against DNS LDH label rules. Explicitly reject names that match IPv4 literal patterns (decimal or hexadecimal). Ensure DNS and IP address parsers are isolated.

---

### 17. HelloRetryRequest State Hijacking via ECH Confirmation Collision

- **Category:** StateConfusion
- **Severity:** medium
- **Confidence:** 0.80
- **Prerequisites:** attacker is on-path, attacker can modify HRR messages
- **Entities:** client, server, attacker

**Description:**

Step 1: An attacker observes a legitimate client initiating an ECH handshake. Step 2: The attacker intercepts the HelloRetryRequest (HRR) from the server and replaces it with a crafted HRR containing a fake 'encrypted_client_hello' extension with an 8-byte payload. Step 3: The attacker computes the transcript hash up to the fake HRR and sets the payload to match the expected confirmation signal. Step 4: The client, believing the server accepted ECH, proceeds to encrypt its second ClientHelloInner using the fake HRR state. Step 5: The attacker forwards the second ClientHello to the server, which fails to decrypt it due to state mismatch, causing a handshake failure or forcing a fallback to a less secure state.

**RFC References:**

- Section backend-server-hrr: "The backend server begins by computing HelloRetryRequest as usual, except that it also contains an 'encrypted_client_hello' extension with a payload of 8 zero bytes. It then computes the transcript hash... Finally, the backend server overwrites the payload... with the following string:"
- Section client-facing-server-hrr: "If the client-facing server accepted ECH, it checks the second ClientHelloOuter also contains the 'encrypted_client_hello' extension. If not, it MUST abort the handshake with a 'missing_extension' alert."

**Mitigation:** Implement strict validation of HRR confirmation signals and ensure that the client-facing server and backend server maintain synchronized state regarding ECH acceptance. Use additional cryptographic binding between the first and second ClientHello to prevent state hijacking.

---

### 18. Quadratic Time Decompression DoS

- **Category:** DenialOfService
- **Severity:** medium
- **Confidence:** 0.80
- **Prerequisites:** Server implementation uses naive extension lookup/copying, No limits on extension list sizes
- **Entities:** client-facing server, attacker

**Description:**

Step 1: Attacker sends a ClientHelloOuter with M extensions and an OuterExtensions list of size N. Step 2: The server implementation uses a naive nested loop to copy extensions from ClientHelloOuter to ClientHelloInner, resulting in O(M*N) processing time. Step 3: By crafting large M and N values, the attacker forces the server to spend excessive CPU cycles on a single handshake message. Step 4: This quadratic time complexity leads to resource exhaustion and denial of service.

**RFC References:**

- Section decompression-amp: "If looking up a ClientHelloOuter extension takes time linear in the number of extensions, the overall decoding process would take O(M*N) time, where M is the number of extensions in ClientHelloOuter and N is the size of OuterExtensions."
- Section encoding-inner: "Quadratic time implementations (such as may happen via naive copying) create a denial of service risk."

**Mitigation:** Implement linear-time outer extension processing as specified in the RFC. Use efficient data structures for extension lookup. Enforce maximum limits on the number of extensions and OuterExtensions list size.

---

### 19. Ambiguous Padding Validation in ClientHelloInner Decompression

- **Category:** ImplementationAmbiguity
- **Severity:** medium
- **Confidence:** 0.80
- **Prerequisites:** Server decompresses EncodedClientHelloInner, Padding length varies or is unexpected
- **Entities:** client, server

**Description:**

Step 1: The client constructs EncodedClientHelloInner with padding bytes set to zero. Step 2: The server decompresses the message and validates the padding. The RFC states that if any padding byte is non-zero, the server MUST abort with an 'illegal_parameter' alert. Step 3: However, the RFC does not explicitly specify how to handle padding that is shorter or longer than expected based on the maximum_name_length or other configuration parameters. This ambiguity could lead to different implementations accepting or rejecting valid padding lengths, potentially causing interoperability issues or allowing padding oracle attacks if not handled consistently.

**RFC References:**

- Section encoding-inner: "The client-facing server computes ClientHelloInner by reversing this process. First it parses EncodedClientHelloInner, interpreting all bytes after as padding. If any padding byte is non-zero, the server MUST abort the connection with an 'illegal_parameter' alert."

**Mitigation:** Implementations should strictly validate padding length against expected values derived from the ECHConfig and ClientHelloInner structure. Any deviation should result in a connection abort to prevent padding oracle attacks.

---

### 20. Ambiguous Handling of Mandatory ECH Configuration Extensions

- **Category:** ImplementationAmbiguity
- **Severity:** medium
- **Confidence:** 0.75
- **Prerequisites:** Server advertises ECHConfig with mandatory extensions, Client does not support one of the mandatory extensions
- **Entities:** client, server

**Description:**

Step 1: The server advertises ECHConfig with mandatory extensions (high order bit set to 1). Step 2: The client parses the extensions and checks for unsupported mandatory ones. Step 3: The RFC states that if an unsupported mandatory extension is present, the client MUST ignore the ECHConfig. However, it does not specify whether the client should attempt to use other ECHConfigs in the list or abort the entire ECH negotiation. This ambiguity could lead to different clients either falling back to a non-ECH connection or failing entirely, impacting interoperability and privacy.

**RFC References:**

- Section config-extensions: "Unlike TLS extensions, an extension can be tagged as mandatory by using an extension type codepoint with the high order bit set to 1. Clients MUST parse the extension list and check for unsupported mandatory extensions. If an unsupported mandatory extension is present, clients MUST ignore the ."

**Mitigation:** Implementations should clearly define the behavior when encountering unsupported mandatory extensions. Clients should attempt to use other available ECHConfigs before falling back to non-ECH connections, ensuring maximum privacy and interoperability.

---

### 21. ClientHelloInner Decompression Amplification Race

- **Category:** RaceCondition
- **Severity:** medium
- **Confidence:** 0.75
- **Prerequisites:** server implementation does not enforce linear-time decompression, server allows duplicate extension references
- **Entities:** client, client-facing server, attacker

**Description:**

Step 1: Attacker crafts a malicious ClientHelloOuter with a large extension and an OuterExtensions list referencing it multiple times. Step 2: Client-facing server begins decompressing EncodedClientHelloInner. Step 3: If the server processes extensions in a way that allows concurrent or interleaved state updates without proper locking or linear-time guarantees, an attacker could potentially exploit a race in the decompression state machine to cause excessive resource consumption or memory allocation races, leading to a denial of service.

**RFC References:**

- Section decompression-amp: "Client-facing servers must decompress EncodedClientHelloInners. A malicious attacker may craft a packet which takes excessive resources to decompress or may be much larger than the incoming packet: If looking up a ClientHelloOuter extension takes time linear in the number of extensions, the overall decoding process would take O(M*N) time... If the same ClientHelloOuter extension can be copied multiple times, an attacker could cause the client-facing server to construct a large ClientHelloInner by including a large extension in ClientHelloOuter, of length L, and an OuterExtensions list referencing N copies of that extension."
- Section linear-outer-extensions: "The following procedure processes the 'ech_outer_extensions' extension in linear time, ensuring that each referenced extension in the ClientHelloOuter is included at most once..."

**Mitigation:** Implement linear-time decompression procedures and reject duplicate extension references in OuterExtensions.

---

### 22. ECHConfig Key Rotation Race

- **Category:** RaceCondition
- **Severity:** medium
- **Confidence:** 0.70
- **Prerequisites:** multi-server deployment, asynchronous configuration updates, DNS caching
- **Entities:** client, client-facing server, backend server, DNS

**Description:**

Step 1: Server initiates ECH key rotation, updating ECHConfig in DNS or configuration store. Step 2: Client fetches new ECHConfig but connection attempt races with old config still being served by some backend nodes. Step 3: If the client-facing server and backend server have inconsistent ECHConfig states due to a race in configuration propagation, decryption may fail, leading to connection retries or fallback to unencrypted ClientHello, potentially leaking SNI.

**RFC References:**

- Section misconfiguration: "It is possible for ECH advertisements and servers to become inconsistent. This may occur, for instance, from DNS misconfiguration, caching issues, or an incomplete rollout in a multi-server deployment. This may also occur if a server loses its ECH keys, or if a deployment of ECH must be rolled back on the server."
- Section compat-issues: "However, in more complex deployment scenarios, this may be difficult to fully guarantee. Thus this protocol was designed to be robust in case of inconsistencies between systems that advertise ECH keys and servers, at the cost of extra round-trips due to a retry."

**Mitigation:** Ensure servers retain support for previously-advertised keys for the duration of their validity. Use retry mechanisms to handle inconsistencies.

---

### 23. Inconsistent Handling of GREASE ECH Extensions

- **Category:** ImplementationAmbiguity
- **Severity:** low
- **Confidence:** 0.90
- **Prerequisites:** Client sends GREASE ECH extension, Server attempts decryption and fails
- **Entities:** client, server

**Description:**

Step 1: A client sends a GREASE 'encrypted_client_hello' extension to provide cover for real ECH usage. Step 2: The server receives the extension and attempts to decrypt it. Since it's GREASE, decryption will fail. Step 3: The RFC states that decryption failure could indicate a GREASE extension, so servers MUST proceed with the connection and rely on the client to abort if ECH was required. However, it also says servers can measure occurrences of the 'ech_required' alert to detect misconfiguration. This ambiguity in how to handle the failure (ignore vs. measure/alert) could lead to inconsistent server behaviors, where some servers might incorrectly log or rate-limit GREASE attempts as malicious traffic.

**RFC References:**

- Section client-facing-server: "Note that decryption failure could indicate a GREASE ECH extension (see ), so it is necessary for servers to proceed with the connection and rely on the client to abort if ECH was required. In particular, the unrecognized value alone does not indicate a misconfigured ECH advertisement ( ). Instead, servers can measure occurrences of the 'ech_required' alert to detect this case."

**Mitigation:** Servers should implement a clear policy for handling GREASE ECH extensions, ensuring they are not logged as errors or malicious attempts. Implementations should distinguish between GREASE failures and actual decryption failures due to misconfiguration.

---

### 24. Padding Length Information Leakage

- **Category:** OversizedPayload
- **Severity:** low
- **Confidence:** 0.80
- **Prerequisites:** Attacker can observe packet lengths, Server anonymity set has varying extension sizes
- **Entities:** client, passive attacker

**Description:**

Step 1: An attacker observes the length of the encrypted ClientHelloInner payload. Step 2: Variations in padding length may reveal information about the underlying plaintext extensions, such as the true SNI or ALPN values, if padding is not applied consistently across the anonymity set.

**RFC References:**

- Section padding: "If the ClientHelloInner is encrypted without padding, then the length of the EncodedClientHelloInner can leak information about ClientHelloInner."
- Section padding-policy: "Variations in the length of the ClientHelloInner ciphertext could leak information about the corresponding plaintext."

**Mitigation:** Clients SHOULD apply deterministic padding to round up extension lengths to the maximum across all profiles and pad the entire message to a multiple of 32 bytes to reduce the set of possible lengths.

---

### 25. ServerHello.random Collision Leading to False ECH Acceptance

- **Category:** MissingValidation
- **Severity:** low
- **Confidence:** 0.75
- **Prerequisites:** attacker or server generates ServerHello.random, cryptographic collision occurs
- **Entities:** client, client-facing server

**Description:**

Step 1: The client-facing server rejects ECH and sends a ServerHello using ClientHelloOuter. Step 2: By chance, the last 8 bytes of the server's ServerHello.random collide with the ECH acceptance confirmation signal derived from the ClientHelloInner. Step 3: The client incorrectly assumes ECH was accepted and proceeds with the handshake using ClientHelloInner preferences, potentially leading to protocol confusion, privacy leaks, or connection failure if the server does not actually support the inner parameters. The probability is 1 in 2^64, but it represents a missing validation of the server's actual intent versus a cryptographic coincidence.

**RFC References:**

- Section attacks-exploiting-acceptance-confirmation: "Suppose the client-facing server terminates the connection (i.e., ECH is rejected or bypassed): if the last 8 bytes of its ServerHello.random coincide with the confirmation signal, then the client will incorrectly presume acceptance and proceed as if the backend server terminated the connection. However, the probability of a false positive occurring for a given connection is only 1 in 2^64."

**Mitigation:** Accept the low probability risk as defined by the protocol. Ensure robust error handling if the handshake fails after false acceptance. Consider additional out-of-band confirmation for high-security contexts.

---

### 26. ECH Configuration Replay

- **Category:** ReplayAttack
- **Severity:** low
- **Confidence:** 0.70
- **Prerequisites:** attacker can intercept DNS or TLS EncryptedExtensions, client caches or trusts replayed ECHConfig without freshness validation
- **Entities:** client, client-facing server

**Description:**

Step 1: Attacker captures a valid ECHConfig structure (including public key, config_id, and extensions) advertised by a client-facing server via DNS or EncryptedExtensions. Step 2: Attacker replays this ECHConfig to a client in a different context or after the configuration has been rotated/revoked, tricking the client into using stale or unauthorized encryption parameters. Step 3: The client encrypts its ClientHelloInner using the replayed ECHConfig, potentially sending sensitive handshake data to an attacker-controlled server or causing a connection failure if the backend server no longer recognizes the config.

**RFC References:**

- Section ech-configuration: "The client-facing server advertises a sequence of ECH configurations to clients, serialized as follows. The structure contains one or more ECHConfig structures in decreasing order of preference."
- Section rejected-ech: "If the server supplied 'retry_configs' and if at least one of the values contains a version supported by the client, the client can regard the ECH keys as securely replaced by the server."

**Mitigation:** Clients should validate ECHConfig freshness using DNS TTLs, certificate validity periods, or explicit versioning. Servers should rotate ECH keys frequently and ensure clients discard stale configurations. RFC 99001 recommends complying with freshness rules (e.g., DNS TTLs) to minimize replay risks.

---

### 27. ECH Configuration Ignorance via GREASE Extension Misinterpretation

- **Category:** StateConfusion
- **Severity:** low
- **Confidence:** 0.70
- **Prerequisites:** server misconfiguration, client sends GREASE ECH
- **Entities:** client, server

**Description:**

Step 1: A client sends a GREASE ECH extension in its initial ClientHello to test server compatibility. Step 2: A misconfigured or malicious server interprets the GREASE extension as a real ECH offer and attempts to decrypt it using its ECHConfig keys. Step 3: Decryption fails, and the server incorrectly transitions to an 'ECH Rejected' state, sending retry_configs. Step 4: The client, expecting the server to ignore the GREASE extension, receives the retry_configs and may incorrectly update its ECH configuration state, leading to tracking or connection failures.

**RFC References:**

- Section grease-ech: "If the server sends an 'encrypted_client_hello' extension in either HelloRetryRequest or EncryptedExtensions, the client MUST check the extension syntactically and abort the connection with a 'decode_error' alert if it is invalid. It otherwise ignores the extension."
- Section client-facing-server: "Note that decryption failure could indicate a GREASE ECH extension, so it is necessary for servers to proceed with the connection and rely on the client to abort if ECH was required."

**Mitigation:** Servers should be configured to recognize and ignore GREASE ECH extensions without transitioning to an ECH rejection state. Clients should validate server responses to GREASE extensions and abort if the server incorrectly processes them.

---

### 28. GREASE ECH Misinterpretation Leading to Authentication Bypass

- **Category:** AuthBypass
- **Severity:** low
- **Confidence:** 0.65
- **Prerequisites:** Server or middlebox implementation incorrectly handles GREASE ECH extensions, Authentication policies are tied to ECH negotiation
- **Entities:** client, server, middlebox

**Description:**

Step 1: The client sends a GREASE ECH extension to mimic real ECH traffic without actually negotiating ECH. Step 2: If a server or middlebox incorrectly interprets the GREASE ECH extension as a real ECH extension, it may attempt to decrypt it or process it as if ECH was negotiated. Step 3: This could lead to the server accepting a connection that it should have rejected, or vice versa, potentially bypassing authentication checks that are dependent on ECH negotiation. Step 4: For example, if the server relies on ECH to enforce certain authentication policies, a misinterpreted GREASE ECH could allow a client to bypass these policies.

**RFC References:**

- Section grease-ech: "If the client attempts to connect to a server and does not have an ECHConfig structure available for the server, it SHOULD send a GREASE 'encrypted_client_hello' extension in the first ClientHello as follows... Offering a GREASE extension is not considered offering an encrypted ClientHello for purposes of requirements in ."

**Mitigation:** Ensure that server and middlebox implementations correctly distinguish between real ECH and GREASE ECH extensions. Implement strict validation of ECHConfig structures and ensure that authentication policies are not solely dependent on the presence of an ECH extension.

---

### 29. Split Mode Forwarding State Race

- **Category:** RaceCondition
- **Severity:** low
- **Confidence:** 0.65
- **Prerequisites:** Split Mode deployment, HelloRetryRequest issued by backend server, client-facing server state management
- **Entities:** client, client-facing server, backend server

**Description:**

Step 1: Client sends ClientHello to client-facing server in Split Mode. Step 2: Client-facing server decrypts ECH and forwards ClientHelloInner to backend server. Step 3: If the backend server sends a HelloRetryRequest, the client-facing server must maintain state to decrypt the second ClientHelloOuter. A race condition in state management between the client-facing server's forwarding logic and backend server's HRR generation could lead to state desynchronization, causing handshake failure or potential information leakage if state is improperly shared or cleared.

**RFC References:**

- Section client-facing-server-hrr: "Note that a client-facing server that forwards the first ClientHello cannot include its own 'cookie' extension if the backend server sends a HelloRetryRequest. This means that the client-facing server either needs to maintain state for such a connection or it needs to coordinate with the backend server to include any information it requires to process the second ClientHello."

**Mitigation:** Client-facing server must maintain state for connections requiring HRR or coordinate with backend server to include necessary information.

---

