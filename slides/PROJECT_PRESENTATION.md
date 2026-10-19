# Network Packet Header Validator

## 1. Project problem

IP and TCP headers contain fields that must appear in a strict order and
remain within valid ranges. Invalid or incomplete headers can be rejected
before later firewall or IDS rules process the packet.

## 2. DFA concept

The validator represents each successful validation step as a DFA state.
IPv4 validation follows:

```text
q0 -> q1 -> q2 -> q3 -> q4 -> q5 -> q6 -> qA
```

Any invalid field moves to `qR`.

## 3. IPv4 fields

The validator checks:

1. Version
2. IHL
3. Complete header length
4. Total Length
5. TTL
6. Protocol

## 4. TCP fields

For TCP packets, a second DFA checks:

1. Source port
2. Destination port
3. Sequence number
4. Acknowledgement number
5. Data offset
6. Reserved bits
7. Flags

## 5. Python implementation

Python's `struct` module decodes the raw IPv4 and TCP bytes. The parser sends
the decoded fields to the DFA. The validator returns the first failed field,
an explanation, and the final DFA state.

## 6. Valid demonstration

Choice 1 input:

```text
version: 4
ihl: 5
total_length: 60
ttl: 64
protocol: 6
```

Output:

```text
VALID
Final state: qA
Protocol name: TCP
Reason: All applicable IPv4 checks passed.
```

## 7. Invalid demonstration

Choice 1 input:

```text
version: 4
ihl: 3
total_length: 60
ttl: 64
protocol: 6
```

Output:

```text
INVALID
Rejected field: ihl
Reason: IHL must be between 5 and 15.
Final state: qR
```

## 8. Firewall mapping

The DFA is a structural gate. A firewall can reject malformed packets before
applying protocol, address, port, flag, or access-control policy rules.

## 9. DFA versus Snort

The DFA validates header structure in a fixed order. Snort uses signatures and
policy rules to match traffic and payload content. The DFA can run before
Snort-style inspection to reject malformed input early.

## 10. Limitations and conclusion

This educational prototype does not capture live traffic, install firewall
rules, inspect payload content, or verify checksums. It demonstrates how
sequential packet-header validation maps to a deterministic finite automaton.