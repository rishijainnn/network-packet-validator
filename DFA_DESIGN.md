# IPv4 and TCP DFA Design

## 1. Introduction

The Network Packet Header Validator uses Deterministic Finite Automata (DFA) to validate IPv4 and TCP packet headers. It checks header fields in a fixed order and rejects a packet when a validation rule fails.

## 2. IPv4 Header Field Order

Version → IHL → Header Length → Total Length → TTL → Protocol

## 3. IPv4 Validations

| Field | Validation Rule |
|---|---|
| Version | Must equal 4 |
| IHL | Must be between 5 and 15 |
| Header Length | IHL × 4 bytes must be present |
| Total Length | Must be at least the header length and must not exceed the received packet size |
| TTL | Must be greater than 0 |
| Protocol | Must be an 8-bit value between 0 and 255 |

## 4. IPv4 DFA States

| State | Meaning |
|---|---|
| q0 | START |
| q1 | VERSION_CHECK |
| q2 | IHL_CHECK |
| q3 | HEADER_LENGTH_CHECK |
| q4 | TOTAL_LENGTH_CHECK |
| q5 | TTL_CHECK |
| q6 | PROTOCOL_CHECK |
| qA | ACCEPT |
| qR | REJECT |

## 5. IPv4 Transition Table

| Current State | PASS | FAIL |
|---|---|---|
| q0 | q1 | qR |
| q1 | q2 | qR |
| q2 | q3 | qR |
| q3 | q4 | qR |
| q4 | q5 | qR |
| q5 | q6 | qR |
| q6 | qA | qR |

Valid path: q0 → q1 → q2 → q3 → q4 → q5 → q6 → qA

Any failed validation leads to qR.

## 6. TCP DFA States

| State | Meaning |
|---|---|
| t0 | START |
| t1 | SOURCE_PORT_CHECK |
| t2 | DESTINATION_PORT_CHECK |
| t3 | SEQUENCE_CHECK |
| t4 | ACKNOWLEDGEMENT_CHECK |
| t5 | DATA_OFFSET_CHECK |
| t6 | RESERVED_BITS_CHECK |
| t7 | FLAGS_CHECK |
| tA | ACCEPT |
| tR | REJECT |

## 7. TCP Validations

| Field | Validation Rule |
|---|---|
| Source Port | 0–65535 |
| Destination Port | 0–65535 |
| Sequence Number | 0–4294967295 |
| Acknowledgement Number | 0–4294967295 |
| Data Offset | 5–15 |
| Reserved Bits | Must equal 0 |
| Flags | Must fit within 9 bits |

## 8. TCP Transition Table

| Current State | PASS | FAIL |
|---|---|---|
| t0 | t1 | tR |
| t1 | t2 | tR |
| t2 | t3 | tR |
| t3 | t4 | tR |
| t4 | t5 | tR |
| t5 | t6 | tR |
| t6 | t7 | tR |
| t7 | tA | tR |

Valid path: t0 → t1 → t2 → t3 → t4 → t5 → t6 → t7 → tA

## 9. Accepting and Rejecting States

The IPv4 accepting state is qA, and the TCP accepting state is tA. The rejecting states are qR and tR, respectively.

The validator rejects a packet at the first failed validation and reports the field and reason for rejection.

## 10. Firewall Processing

The DFA acts as a structural validation stage before firewall policy checks. After structural validation, additional rules can check addresses, ports, flags, and access permissions. A structurally valid packet is not automatically trusted.

## 11. Limitations

This educational project does not capture live network traffic, install firewall rules, or verify IP/TCP checksums.