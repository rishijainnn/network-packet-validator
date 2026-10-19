
"""Explicit deterministic finite automaton for IPv4 header validation."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any


@dataclass
class ValidationResult:
    valid: bool
    final_state: str
    failed_field: str | None = None
    reason: str = ""
    parsed_fields: dict[str, Any] = field(default_factory=dict)


class IPv4HeaderDFA:
    states = {
        "q0": "START",
        "q1": "VERSION_CHECK",
        "q2": "IHL_CHECK",
        "q3": "HEADER_LENGTH_CHECK",
        "q4": "TOTAL_LENGTH_CHECK",
        "q5": "TTL_CHECK",
        "q6": "PROTOCOL_CHECK",
        "qA": "ACCEPT",
        "qR": "REJECT",
    }

    initial_state = "q0"
    accepting_states = {"qA"}
    reject_state = "qR"
    alphabet = {"PASS", "FAIL"}

    @classmethod
    def transition_table(cls) -> list[dict[str, str]]:
        checks = [
            ("q0", "q1", "Version check"),
            ("q1", "q2", "IHL check"),
            ("q2", "q3", "Complete header check"),
            ("q3", "q4", "Total Length check"),
            ("q4", "q5", "TTL check"),
            ("q5", "q6", "Protocol check"),
            ("q6", "qA", "Accept"),
        ]

        rows = [
            {
                "from": start,
                "symbol": "PASS",
                "to": end,
                "description": description,
            }
            for start, end, description in checks
        ]

        rows.extend(
            {
                "from": state,
                "symbol": "FAIL",
                "to": "qR",
                "description": "Reject on first failure",
            }
            for state, _, _ in checks
        )

        return rows

    @classmethod
    def validate_fields(
        cls,
        fields: dict[str, Any],
        *,
        complete_packet: bool = False,
    ) -> ValidationResult:
        work = dict(fields)
        result = ValidationResult(
            False,
            cls.initial_state,
            parsed_fields=work,
        )

        checks = [
            (
                "version",
                "Version must equal 4.",
                lambda: cls._integer(work, "version") == 4,
                "q1",
            ),
            (
                "ihl",
                "IHL must be between 5 and 15.",
                lambda: 5 <= cls._integer(work, "ihl") <= 15,
                "q2",
            ),
            (
                "header_length",
                "The complete IHL-indicated header is not present.",
                lambda: cls._header_present(work),
                "q3",
            ),
            (
                "total_length",
                "Total Length is inconsistent with the header or packet size.",
                lambda: cls._total_length(work, complete_packet),
                "q4",
            ),
            (
                "ttl",
                "TTL must be greater than zero under the forwarding policy.",
                lambda: cls._integer(work, "ttl") > 0,
                "q5",
            ),
            (
                "protocol",
                "Protocol must be an 8-bit value from 0 to 255.",
                lambda: 0 <= cls._integer(work, "protocol") <= 255,
                "q6",
            ),
        ]

        for field_name, default_reason, predicate, next_state in checks:
            try:
                passed = predicate()
            except ValueError as exc:
                result.failed_field = field_name
                result.reason = str(exc)
                result.final_state = cls.reject_state
                return result

            if not passed:
                result.failed_field = field_name
                result.reason = default_reason
                result.final_state = cls.reject_state
                return result

            result.final_state = next_state

        result.valid = True
        result.final_state = "qA"
        result.reason = "All applicable IPv4 checks passed."
        result.parsed_fields = work

        return result

    @staticmethod
    def _integer(fields: dict[str, Any], name: str) -> int:
        value = fields.get(name)

        if value is None:
            raise ValueError(f"{name} is missing.")

        try:
            return int(value)
        except (TypeError, ValueError) as exc:
            raise ValueError(f"{name} is not numeric.") from exc

    @classmethod
    def _header_present(cls, fields: dict[str, Any]) -> bool:
        ihl = cls._integer(fields, "ihl")
        packet_size = fields.get("packet_size")

        return packet_size is None or int(packet_size) >= ihl * 4

    @classmethod
    def _total_length(
        cls,
        fields: dict[str, Any],
        complete_packet: bool,
    ) -> bool:
        total_length = cls._integer(fields, "total_length")
        ihl = cls._integer(fields, "ihl")

        if total_length < ihl * 4:
            return False

        if complete_packet:
            packet_size = fields.get("packet_size")
            return packet_size is not None and total_length <= int(packet_size)

        return True


class TCPHeaderDFA:
    """DFA for fixed-order structural checks in a TCP header."""

    states = {
        "t0": "START",
        "t1": "SOURCE_PORT_CHECK",
        "t2": "DESTINATION_PORT_CHECK",
        "t3": "SEQUENCE_CHECK",
        "t4": "ACKNOWLEDGEMENT_CHECK",
        "t5": "DATA_OFFSET_CHECK",
        "t6": "RESERVED_BITS_CHECK",
        "t7": "FLAGS_CHECK",
        "tA": "ACCEPT",
        "tR": "REJECT",
    }

    initial_state = "t0"
    accepting_states = {"tA"}
    reject_state = "tR"

    @classmethod
    def validate_fields(cls, fields: dict[str, Any]) -> ValidationResult:
        work = dict(fields)
        result = ValidationResult(
            False,
            cls.initial_state,
            parsed_fields=work,
        )

        checks = [
            (
                "source_port",
                "Source port must be between 0 and 65535.",
                lambda: 0 <= cls._integer(work, "source_port") <= 65535,
                "t1",
            ),
            (
                "destination_port",
                "Destination port must be between 0 and 65535.",
                lambda: 0 <= cls._integer(work, "destination_port") <= 65535,
                "t2",
            ),
            (
                "sequence_number",
                "Sequence number must be a 32-bit value.",
                lambda: 0 <= cls._integer(work, "sequence_number") <= 0xFFFFFFFF,
                "t3",
            ),
            (
                "acknowledgement_number",
                "Acknowledgement number must be a 32-bit value.",
                lambda: 0 <= cls._integer(work, "acknowledgement_number") <= 0xFFFFFFFF,
                "t4",
            ),
            (
                "data_offset",
                "TCP data offset must be between 5 and 15.",
                lambda: 5 <= cls._integer(work, "data_offset") <= 15,
                "t5",
            ),
            (
                "reserved",
                "TCP reserved bits must be zero.",
                lambda: cls._integer(work, "reserved") == 0,
                "t6",
            ),
            (
                "flags",
                "TCP flags must fit in 9 bits.",
                lambda: 0 <= cls._integer(work, "flags") <= 0x1FF,
                "t7",
            ),
        ]

        for field_name, default_reason, predicate, next_state in checks:
            try:
                passed = predicate()
            except ValueError as exc:
                result.failed_field = f"tcp_{field_name}"
                result.reason = str(exc)
                result.final_state = cls.reject_state
                return result

            if not passed:
                result.failed_field = f"tcp_{field_name}"
                result.reason = default_reason
                result.final_state = cls.reject_state
                return result

            result.final_state = next_state

        result.valid = True
        result.final_state = "tA"
        result.reason = "All TCP header checks passed."

        return result

    @classmethod
    def transition_table(cls) -> list[dict[str, str]]:
        checks = [
            ("t0", "t1", "Source port check"),
            ("t1", "t2", "Destination port check"),
            ("t2", "t3", "Sequence number check"),
            ("t3", "t4", "Acknowledgement number check"),
            ("t4", "t5", "Data offset check"),
            ("t5", "t6", "Reserved bits check"),
            ("t6", "t7", "Flags check"),
            ("t7", "tA", "Accept"),
        ]

        rows = [
            {
                "from": start,
                "symbol": "PASS",
                "to": end,
                "description": description,
            }
            for start, end, description in checks
        ]

        rows.extend(
            {
                "from": state,
                "symbol": "FAIL",
                "to": "tR",
                "description": "Reject on first failure",
            }
            for state, _, _ in checks
        )

        return rows

    @staticmethod
    def _integer(fields: dict[str, Any], name: str) -> int:
        value = fields.get(name)

        if value is None:
            raise ValueError(f"{name} is missing.")

        try:
            return int(value)
        except (TypeError, ValueError) as exc:
            raise ValueError(f"{name} is not numeric.") from exc
