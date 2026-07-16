# Meta-Analysis: DeepSeek Security Analysis of 6 IETF Drafts

**Analyst:** Claude Opus 4.6 (manual review of automated output)
**Date:** 2026-05-04
**Model under review:** deepseek-chat
**Tool:** ietf-draft-analyzer

## Drafts Analyzed

| Draft | Protocol Label | Leads | Tokens | Duration |
|-------|---------------|-------|--------|----------|
| draft-ietf-6lo-nd-gaao-09 | 6lo-nd-gaao | 8 | 90,696 | 94s |
| draft-ietf-6lo-path-aware-semantic-addressing-13 | 6lo-pasa | 43 | 208,385 | 190s |
| draft-ietf-dnsop-structured-dns-error-19 | dns-structured-error | 52 | 68,382 | 235s |
| draft-ietf-intarea-rfc8335bis-04 | rfc8335bis | 39 | 83,576 | 201s |
| draft-ietf-scitt-scrapi-09 | scitt-scrapi | 24 | 45,629 | 120s |
| draft-ietf-intarea-v4-via-v6-08 | v4-via-v6 | 19 | 23,057 | 101s |
| **Total** | | **185** | **519,725** | **941s** |

## Executive Summary

The tool successfully identifies security-relevant protocol mechanisms in each draft
and generates plausible attack narratives backed by accurate RFC quotations. However,
the output requires heavy post-processing before it is useful to a human reviewer.

The core problems are:

1. **Severe semantic duplication** — the same vulnerability is re-reported under
   every attack category it can be stretched to fit. After deduplication, roughly
   60-70 distinct findings remain out of the reported 185.
2. **Category misclassification** — leads are shoehorned into categories that
   do not match the actual attack type.
3. **Most findings restate the draft's own Security Considerations** rather than
   discovering novel issues.

After filtering for duplicates, misclassifications, and restated known issues,
approximately 10-15 findings across all six drafts are genuinely interesting
and potentially actionable for the draft authors.

---

## Part 1: Assessment of the Tool

### 1.1 Duplication

This is the single biggest quality problem. The tool runs 10 attack categories
independently against each draft. When it finds a vulnerability, it reports it
once per category it can be made to fit, each time with slightly different
wording but the same underlying attack. The fingerprint-based deduplication
prevents exact duplicates but completely misses semantic duplicates.

Worst offenders:

| Core Finding | Draft | Times Reported | Categories Used |
|-------------|-------|---------------|-----------------|
| Address exhaustion via impersonation | 6lo-pasa | ~10 | MissingValidation, AuthBypass, DoS, StateConfusion, RaceCondition, OversizedPayload, Downgrade, ImplementationAmbiguity, InformationLeak |
| EDE EXTRA-TEXT injection via legacy forwarders | dns-structured-error | ~7 | AuthBypass, ReplayAttack, DoS, StateConfusion, ImplementationAmbiguity, MissingValidation, Downgrade |
| ICMP source address spoofing via dummy 192.0.0.8 | v4-via-v6 | ~7 | ImplementationAmbiguity, ReplayAttack, StateConfusion, AuthBypass, DoS, Downgrade, InformationLeak |
| Topology disclosure via TAAF addresses | 6lo-pasa | ~6 | InformationLeak, AuthBypass, StateConfusion, MissingValidation, ImplementationAmbiguity, Downgrade |
| Covert channel via optional data field | rfc8335bis | 3 | InformationLeak, DoS, AuthBypass |
| Contact URI automatic connection | dns-structured-error | ~4 | MissingValidation, StateConfusion, DoS, ImplementationAmbiguity |
| Unauthenticated HTTP metadata routing | scitt-scrapi | ~5 | ImplementationAmbiguity, MissingValidation, StateConfusion, AuthBypass, DoS |
| IPv4 reachability assumption violation | v4-via-v6 | ~5 | StateConfusion, MissingValidation, DoS, ImplementationAmbiguity, Downgrade |

The 10 attack categories function as a multiplication factor rather than a
classification tool. A single vulnerability reported 7 times under different
headings does not represent 7 distinct security issues.

### 1.2 Category Misclassification

Many leads are assigned to categories that do not match the described attack:

| Lead | Assigned Category | Better Fit |
|------|------------------|------------|
| Address Exhaustion via Impersonation | OversizedPayload | DenialOfService |
| Address Exhaustion via Impersonation | RaceCondition | DenialOfService |
| Topology Disclosure via TAAF | AuthBypass | InformationLeak |
| Info Leakage via Interface Enumeration | DenialOfService | InformationLeak |
| DoS via Amplification | AuthBypass | DenialOfService |
| ICMP Spoofing via Dummy Address | ReplayAttack | ImplementationAmbiguity |
| Race Condition in Client Processing | RaceCondition | MissingValidation |
| Certificate Error Exploitation | StateConfusion | Downgrade |

The LLM treats categories as tags (multiple can apply) rather than as
classifications (pick the best one). This inflates the apparent breadth of
the attack surface.

### 1.3 Relationship to Draft Security Considerations

For most drafts, the tool re-discovers what the authors already documented:

- **rfc8335bis**: L-bit manipulation, interface enumeration, cross-VPN leakage,
  rate-limiting, covert channel — all in the draft's Security Considerations.
- **dns-structured-error**: Unauthenticated transport, legacy forwarder injection,
  contact URI abuse — all covered extensively.
- **v4-via-v6**: Dummy address 192.0.0.8, reachability assumption — the draft's
  two primary security topics.
- **6lo-pasa**: TAAF topology disclosure, address exhaustion — acknowledged in
  Section 13.
- **6lo-nd-gaao**: Address exhaustion, GAAO-specific concerns — Section 8.

This is not entirely a weakness: confirming that the Security Considerations
section is complete has value. But the tool presents these as discoveries
rather than confirmations, which overstates its contribution.

### 1.4 Severity Calibration

- The 14 critical findings are mostly standard attack patterns (impersonation,
  injection on unauthenticated channels) where the draft already specifies
  mitigations. A genuinely critical finding would be one with no documented
  mitigation.
- High confidence scores (0.85-0.95) are overused as defaults. Many findings
  rated 0.85 require preconditions that are unlikely or already addressed.
- The best-calibrated draft is **6lo-nd-gaao** (8 leads, no criticals, focused).
- The worst-calibrated is **6lo-pasa** (43 leads, 5 criticals, extreme duplication).

### 1.5 Lead Count Versus Actual Attack Surface

The per-draft lead counts (8 to 52) correlate more with draft length and the
amount of security text available than with actual vulnerability density. The
DNS structured error draft is not 6x more vulnerable than the GAAO draft — it
simply has more text for the LLM to pattern-match against.

### 1.6 Recommendations for Tool Improvement

1. **Semantic deduplication**: Before emitting leads, cluster by core
   vulnerability (same RFC quote, same attack chain) and merge across
   categories. Report the primary category and note secondary relevance
   as tags.

2. **Single-pass category assignment**: Instead of running all 10 categories
   independently, run one analysis pass and let the model assign the best-fit
   category. This eliminates the multiplication effect.

3. **Known/novel flag**: Cross-reference findings against the draft's own
   Security Considerations section. Findings that restate documented concerns
   should be flagged as "confirmed" rather than presented as discoveries.

4. **Severity adjustment for mitigated issues**: If the draft specifies a
   MUST-level mitigation for a concern, the severity should reflect that the
   spec addresses it. "DoS without rate-limiting" when the spec says
   "implementations MUST rate-limit" is a medium at best, not high.

5. **Confidence recalibration**: Reserve 0.9+ for findings with concrete,
   protocol-level attack chains. Theoretical issues requiring multiple
   unlikely preconditions should sit at 0.5-0.7.

---

## Part 2: Interesting Findings

The following findings, extracted from the 185 leads, represent issues that
are either novel (not explicitly covered in the draft's Security Considerations),
highlight a real specification gap, or identify an under-specified failure mode
that implementers might miss. They are organized by draft.

### 2.1 draft-ietf-scitt-scrapi-09

#### F1: Unauthenticated HTTP Metadata Used for Profile Routing

**Original severity:** HIGH | **Adjusted assessment:** HIGH — this is the strongest finding across all six drafts

The draft acknowledges (Section sec-use-of-unauthenticated-http-metadata) that
implementations may use HTTP headers or distinct endpoints to route Signed
Statements to profile-specific processing. These signals are:

- Not signed
- Not committed to the Verifiable Data Structure
- Not replayable by Auditors

This means an on-path attacker can manipulate request headers to route a
Signed Statement to a different profile's processing pipeline, potentially
applying a weaker Registration Policy. Because the routing decision is not
captured in the audit trail, the attack is invisible to Auditors.

**Why this matters:** The entire SCITT architecture depends on auditability.
A registration decision influenced by unauthenticated, unauditable inputs
undermines the core security guarantee. The draft warns against it but does
not mandate that implementations derive routing solely from authenticated
data (protected headers or payload content).

**Recommendation to authors:** Consider strengthening the language from
"implementations SHOULD NOT use unauthenticated signals as authoritative
inputs" to a MUST-level requirement, or require that the profile identifier
used for routing be committed to the Verifiable Data Structure so Auditors
can verify it.

> RFC 99006, Section sec-use-of-unauthenticated-http-metadata:
> *"Implementations that serve multiple application profiles use
> unauthenticated HTTP-layer signals, such as request headers or distinct
> registration endpoints, to route incoming Signed Statements to
> profile-specific processing. However, these signals are not signed, are
> not committed to the Verifiable Data Structure, and cannot be replayed
> by Auditors."*

#### F2: Authentication Explicitly Out of Scope

**Original severity:** HIGH | **Adjusted assessment:** MEDIUM-HIGH

The draft states: *"Authentication is out of scope for this document.
Implementations authenticate clients."* This is a deliberate design choice,
but it means:

- There is no baseline authentication requirement for registration endpoints
- Implementations will vary wildly (some may have none)
- The DoS attack surface is entirely implementation-dependent

For a protocol whose purpose is to provide supply-chain transparency,
punting on authentication creates a gap that deployments must fill
independently. The draft could benefit from a normative reference to a
minimum authentication profile (e.g., mutual TLS or OAuth 2.0 with
specific grant types).

> RFC 99006, Section sec-authentication:
> *"Authentication is out of scope for this document. Implementations
> authenticate clients, for example for the purposes of authorization or
> preventing denial of service attacks."*

#### F3: Race Condition Between Receipt Issuance and Key Rotation

**Original severity:** HIGH | **Adjusted assessment:** MEDIUM

A client obtains a Receipt, then later queries the key discovery resource
to verify it. If the Transparency Service rotates keys between issuance
and verification, the client may retrieve a key set that no longer includes
the signing key. The draft says retired keys should remain available for
"a reasonable delay" — but "reasonable" is not defined.

This is primarily an interoperability concern: different services will
choose different key retirement windows, and clients cannot predict when
verification will fail. A concrete minimum retention period (e.g., "at
least as long as the longest Receipt TTL") would help.

> RFC 99006, Section sec-transparency-service-keys:
> *"The Transparency Service stop returning at that resource the keys it
> no longer uses to issue Receipts, following a reasonable delay."*

#### F4: Detached Payload TOCTOU

**Original severity:** CRITICAL | **Adjusted assessment:** MEDIUM

When a Signed Statement uses a detached payload, the Transparency Service
must fetch the payload via an "implementation-specific mechanism" to verify
the signature. If the payload can be modified between fetch and commit,
the logged statement may not match what was verified. This is a classic
TOCTOU issue. The severity depends entirely on the implementation (e.g.,
content-addressed storage eliminates it), but the specification provides
no guidance on avoiding it.

> RFC 99006, Section sec-register-signed-statement:
> *"When a Signed Statement is submitted with a detached payload, the
> Transparency Service still requires access to the payload content in
> order to verify the signature as part of applying the Registration
> Policy. The mechanism by which the payload is made available to the
> Transparency Service is implementation-specific."*

---

### 2.2 draft-ietf-6lo-path-aware-semantic-addressing-13

#### F5: Forwarding Loop at Root Due to Address Length Ambiguity

**Original severity:** HIGH | **Adjusted assessment:** MEDIUM-HIGH

The PASA forwarding algorithm (Section 7.1) specifies:

1. If Len(DA) equals Len(CA), go to step 4
2. Step 4: If DA and CA are the same, the packet arrived — exit
3. Otherwise, send the packet to the parent node and exit

At the root node, there is no parent. If an attacker crafts a packet with
a destination address that has the same length as the root's address but
differs in value, the root has no valid action: it cannot forward to a
parent (none exists) and the spec does not say to drop the packet.

Depending on the implementation, this could cause:
- A crash or error
- The packet being forwarded to a child (loop)
- Silent drop (best case, but not specified)

**Recommendation:** Add an explicit rule: "If a node has no parent and
the destination address does not match the current address, drop the
packet and send an ICMPv6 No Route to Host notification."

> RFC 99003, Section 7.1:
> *"If length of DA is equal to length of CA, go to step 4. ... If DA
> and CA are the same, the packet arrived at destination, exit.
> Otherwise, send the packet to parent node and exit."*

#### F6: TOCTOU in Address Assignment

**Original severity:** HIGH | **Adjusted assessment:** MEDIUM

When two nodes simultaneously request addresses from the same PASA Router,
the router could assign the same address to both if it does not use atomic
operations. The sequence is:

1. Node A sends NS with GAAO
2. Node B sends NS with GAAO
3. Router checks pool, selects next address for A
4. Router checks pool, selects same next address for B (index not yet incremented)
5. Both nodes receive the same address

This is a standard concurrency bug, not a protocol-level flaw per se, but
the specification does not mention the need for atomic address assignment.
On constrained 6LoWPAN devices where concurrency primitives may be limited,
this could be a real implementation trap.

> RFC 99003, Section 10:
> *"The parent, acting as IPv6 ND Registrar will process the received
> GAAO message and act according to [I-D.ietf-6lo-nd-gaao], and the
> corresponding GAAO message for the NA packet is generated."*

#### F7: Non-Volatile Memory Loss Causing Address Collisions

**Original severity:** CRITICAL | **Adjusted assessment:** MEDIUM

The draft requires (MUST) that PASA Routers store 'r' and 'h' indexes in
non-volatile memory. If a router reboots and this storage is lost or
corrupted, the indexes reset to 0 and the router will reassign addresses
that may still be in use by other nodes.

The draft correctly identifies this requirement, but does not specify a
recovery procedure. There is no Duplicate Address Detection (DAD) step
after reboot, no mechanism to detect that a reassigned address is still
live, and no guidance on how long to wait before reassigning.

On constrained IoT devices, non-volatile write endurance is limited, and
"MUST store in non-volatile memory" may not survive the lifetime of the
device.

> RFC 99003, Section 6.1:
> *"These two indexes MUST be stored in non-volatile memory along with
> address assignment state, so that in case of reboot a PASA-Router can
> continue its role without disrupting the addressing."*

#### F8: TAAF Topology Disclosure to External Observers

**Original severity:** HIGH | **Adjusted assessment:** HIGH — well-identified, under-mitigated

TAAF-generated addresses encode the full path from root to node in the
address bits themselves. An external observer who sees a PASA address
(e.g., in an IPv6 packet header leaving the domain) can decode the
binary representation to reconstruct the network tree:

    2001:db8::2B = b101011
    Path: 1 -> 10 -> 1010 -> 101011
    Meaning: root -> router -> router -> host

This reveals:
- Number of hops from root
- Parent-child relationships
- Whether a node is a router or host (trailing bit)
- Approximate network size (if multiple addresses observed)

The draft acknowledges this (Section 14) and recommends using opaque
addresses for external communications, but this is only a SHOULD. For
networks where topology secrecy matters (e.g., military or critical
infrastructure IoT), this is a significant design trade-off that should
be made explicit and prominent.

> RFC 99003, Section 14:
> *"Depending on the AAF, the algorithmically built addresses may reveal
> topology information outside the PASA Domain. In particular the Tree
> Assignment Function (TAAF) proposed in this specification reveals the
> path between the root and a node."*

---

### 2.3 draft-ietf-dnsop-structured-dns-error-19

#### F9: Legacy DNS Forwarder as Injection Vector

**Original severity:** HIGH | **Adjusted assessment:** HIGH

A DNS proxy or forwarder that predates EDE awareness will blindly forward
EDE options it does not understand. An attacker on-path between the
upstream resolver and the legacy forwarder can inject or modify the
EXTRA-TEXT field. The forwarder passes the attacker-controlled content
to the client without validation.

This is the most practical attack vector in the draft because:
- Legacy forwarders are extremely common (home routers, corporate proxies)
- The client may trust the forwarder as its configured resolver
- The injected content (contact URIs, organization names) directly
  influences end-user behavior

The draft addresses this by recommending clients only process EDE from
"explicitly configured DNS servers" or use RESINFO, but client
implementations that trust their local forwarder (common default) remain
vulnerable.

> RFC 99002, Section security-risks-from-legacy-dns-forwarders:
> *"An attacker might inject (or modify) the EDE EXTRA-TEXT field with
> a DNS proxy or DNS forwarder that is unaware of EDE. Such a DNS proxy
> or DNS forwarder will forward that attacker-controlled EDE option."*

#### F10: Automatic Connection Initiation from Contact URIs

**Original severity:** HIGH | **Adjusted assessment:** MEDIUM-HIGH

If a client automatically initiates connections to URIs in the 'c' field
(rather than just displaying them), a resolver can:

- Silently report client DNS activity to third parties
- Trigger denial-of-service reflection attacks
- Entrap a client by causing it to connect to malicious services

The draft restricts allowed URI schemes to 'sips', 'tel', and 'mailto'
specifically to prevent automatic HTTP connections. However:

1. Not all implementations will enforce the scheme restriction
2. Even 'tel:' and 'mailto:' can be abused (toll-fraud via premium numbers,
   email harvesting)
3. The restriction depends on the client correctly parsing and validating
   the URI scheme before any action

**Recommendation:** The draft should explicitly state that clients MUST NOT
automatically initiate any connection (including opening a mail client or
phone dialer) without explicit user action.

> RFC 99002, Section restrictions-on-display-of-c-o-and-j-fields:
> *"Clients automatically initiate connections to URIs derived from the
> EXTRA-TEXT field. Doing so could allow a resolver to silently report
> client activity to third parties, enable denial-of-service reflection
> attacks, or be used to entrap a client."*

#### F11: Organization Name ('o' field) as Social Engineering Vector

**Original severity:** MEDIUM | **Adjusted assessment:** MEDIUM

The 'o' field contains a human-readable organization name that is displayed
to end users. The draft requires validation against a registry or heuristic
check. However:

- No specific registry is mandated
- "Heuristics" for detecting embedded instructions or URLs are undefined
- An attacker who controls a resolver can set 'o' to text that mimics a
  trusted organization (e.g., "Microsoft Security Team - Call 1-800-...")

The field is designed to build trust ("this block was applied by your ISP"),
but without a concrete validation mechanism, it becomes a social engineering
channel.

> RFC 99002, Section restrictions-on-display-of-c-o-and-j-fields:
> *"Further, clients display the value of the field to the end user unless
> one of the following conditions is met: The value matches a registered
> organization name listed in the [registry] OR The value consists solely
> of an organization name and does not contain any additional free-form
> content such as instructions, URLs, or messaging intended to influence
> end user behavior."*

---

### 2.4 draft-ietf-intarea-rfc8335bis-04

#### F12: Split Checksum Design for Optional Data

**Original severity:** MEDIUM | **Adjusted assessment:** MEDIUM

The ICMP Extension Structure checksum covers only the Interface
Identification Object. Any trailing optional data is covered only by
the ICMP header checksum, which is not cryptographic.

This means an on-path attacker can modify the optional data field without
invalidating the Extension Structure checksum. While the ICMP header
checksum would catch random corruption, a deliberate attacker can
recompute it. The practical impact is limited (the data field is opaque
and should not be interpreted), but it creates a discrepancy in integrity
coverage that could confuse implementers.

> RFC 99001, Section dontdothis:
> *"The ICMP Extension Structure checksum covers only the Interface
> Identification Object. Any data following it is not covered by this
> checksum but is covered by the ICMP header checksum."*

#### F13: L-bit / Interface Identification Object Consistency Gap

**Original severity:** HIGH | **Adjusted assessment:** MEDIUM

When L-bit is set, the Interface Identification Object can identify
the probed interface by name, index, or address. When L-bit is clear,
identification must be by address only. However, the specification does
not explicitly require the receiver to validate this consistency.

An attacker could send a request with L-bit clear but identify by name
or index. If the receiver does not check, it might process the request
under the wrong access control rules (L-bit clear may have different
authorized source prefix lists than L-bit set).

The draft lists this as a malformed-query condition in the processing
section, but the validation requirement could be stated more explicitly
as a MUST.

> RFC 99001, Section ExtendedEcho:
> *"If the L-bit is set, the Interface Identification Object can identify
> the probed interface by name, index, or address. If the L-bit is clear,
> the Interface Identification Object identify the probed interface by
> address."*

---

### 2.5 draft-ietf-intarea-v4-via-v6-08

#### F14: Reachability Assumption Violation

**Original severity:** CRITICAL | **Adjusted assessment:** HIGH

This is the most operationally significant finding for this draft. If
IPv4-only hosts sit behind routers that lack IPv4 addresses, a network
administrator may reasonably assume those hosts are unreachable from the
IPv4 Internet. Enabling v4-via-v6 routing on the intermediary routers
breaks this assumption silently.

The danger is that this is not a bug or missing validation — it is the
intended behavior of the protocol working as designed. The security
impact comes from the mismatch between operator expectations and protocol
behavior. The draft documents this clearly, but it deserves prominent
operational guidance (perhaps a dedicated "Operational Considerations"
section or a BCP-style warning).

> RFC 99005, Section security-considerations:
> *"if an island of IPv4-only hosts is separated from the IPv4 Internet
> by routers that have not been assigned IPv4 addresses, a network
> administrator might reasonably assume that the IPv4-only hosts are
> unreachable from the IPv4 Internet. This assumption is broken if the
> intermediary routers implement v4-via-v6 routing"*

#### F15: Dummy Address 192.0.0.8 as Shared ICMP Source

**Original severity:** HIGH | **Adjusted assessment:** MEDIUM-HIGH

When a router has no IPv4 addresses, it uses 192.0.0.8 as the source of
ICMPv4 packets. This creates three problems:

1. **Firewall filtering**: Packets from 192.0.0.8 may be dropped as spoofed,
   breaking Path MTU Discovery and causing persistent traffic black-holing.
2. **Debugging ambiguity**: Multiple routers using the same source address
   makes traceroute and fault isolation impossible for the affected hops.
3. **Spoofing opportunity**: An attacker can send ICMP packets with source
   192.0.0.8 and they will be indistinguishable from legitimate router-generated
   ICMP, potentially triggering PMTU reduction or other ICMP-driven behavior.

The draft documents all three problems but offers only "assign an IPv4
address" as the mitigation — which defeats the purpose of v4-via-v6 routing
on addressless routers. A more robust solution might be worth exploring
(e.g., a mechanism to derive a unique per-router dummy address from a
reserved range).

> RFC 99005, Section sec-icmp:
> *"Using the dummy address as the source of ICMPv4 packet causes a number
> of drawbacks: using the same address on multiple routers may hamper
> debugging and fault isolation; packets originating from 192.0.0.8 might
> be considered as spoofed traffic and dropped by firewalls at network
> boundaries."*

---

### 2.6 draft-ietf-6lo-nd-gaao-09

#### F16: AAF Not Used Error Loop

**Original severity:** HIGH | **Adjusted assessment:** MEDIUM

When a node receives status 13 (AAF Not Used), it has three options:
re-issue without AAF, re-issue with a different AAF, or do nothing. The
draft notes that retrying with different AAFs "may lead to repeated
requests that may consume bandwidth and energy."

On constrained 6LoWPAN devices, this is a meaningful concern. An attacker
who can spoof NA(GAAO) responses with status 13 can force a node into a
retry loop, draining its battery. The draft does not mandate:

- A maximum retry count
- A backoff interval between retries
- A mechanism to distinguish legitimate AAF-Not-Used from spoofed responses

**Recommendation:** Add normative guidance: "Nodes SHOULD NOT retry more
than [N] times and MUST implement exponential backoff between retries."

> RFC 99004, Section 5.4:
> *"When the node receives this status back it SHOULD perform one of the
> following actions: ... Re-issue the same request with a different AAF.
> ... Note that such an approach may lead to repeated requests that may
> consume bandwidth and energy."*

#### F17: R-flag Address Reservation Without Timeout Guidance

**Original severity:** MEDIUM | **Adjusted assessment:** MEDIUM

When a 6LR sets the R-flag in NA(GAAO), it indicates that the address is
offered but not yet registered. The node must explicitly register within
RETRANS_TIMER * MAX_UNICAST_SOLICIT. During this window, the address
state is ambiguous:

- Is it reserved (unavailable to others)?
- Is it tentative (could be given to another requester)?
- What happens if the node never registers?

An attacker can request addresses, receive R-flag responses, and never
register — tying up addresses until the timeout expires. On networks
with small address pools, this is an effective low-rate DoS.

The draft specifies the timeout but does not clarify the address state
during the waiting period. Implementers may handle it differently,
leading to interoperability issues.

> RFC 99004, Section 5.2:
> *"When setting the R-flag, and as for [RFC4861], the 6LR is expect to
> receive a registration within RETRANS_TIMER multiplied by
> MAX_UNICAST_SOLICIT. If no registration is received within this amount
> of time the 6LR will consider that address/prefix is not in use by the
> requesting 6LN."*

---

## Summary of Interesting Findings

| ID | Draft | Finding | Adjusted Severity | Novel? |
|----|-------|---------|-------------------|--------|
| F1 | scitt-scrapi | Unauthenticated HTTP metadata for profile routing | HIGH | Partially — draft warns but SHOULD-level |
| F2 | scitt-scrapi | Authentication out of scope | MEDIUM-HIGH | Known design choice, gap remains |
| F3 | scitt-scrapi | Key rotation / receipt verification race | MEDIUM | Novel timing concern |
| F4 | scitt-scrapi | Detached payload TOCTOU | MEDIUM | Novel for this context |
| F5 | 6lo-pasa | Forwarding loop at root (address length ambiguity) | MEDIUM-HIGH | Novel — spec gap |
| F6 | 6lo-pasa | TOCTOU in address assignment | MEDIUM | Novel for constrained devices |
| F7 | 6lo-pasa | NVM loss causing address collisions | MEDIUM | Known requirement, missing recovery |
| F8 | 6lo-pasa | TAAF topology disclosure | HIGH | Known but under-mitigated |
| F9 | dns-structured-error | Legacy forwarder injection vector | HIGH | Known but most practical attack |
| F10 | dns-structured-error | Automatic connection from contact URIs | MEDIUM-HIGH | Known, scheme restriction helps |
| F11 | dns-structured-error | Organization name social engineering | MEDIUM | Partially novel |
| F12 | rfc8335bis | Split checksum for optional data | MEDIUM | Novel framing of known design |
| F13 | rfc8335bis | L-bit / identification object consistency | MEDIUM | Known, needs stronger language |
| F14 | v4-via-v6 | Reachability assumption violation | HIGH | Known, needs operational prominence |
| F15 | v4-via-v6 | Dummy 192.0.0.8 shared ICMP source | MEDIUM-HIGH | Known, mitigation is weak |
| F16 | 6lo-nd-gaao | AAF Not Used error loop | MEDIUM | Novel retry concern |
| F17 | 6lo-nd-gaao | R-flag address reservation ambiguity | MEDIUM | Novel state ambiguity |
