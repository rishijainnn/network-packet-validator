
"""Hexadecimal and binary IPv4 packet parsing."""

from __future__ import annotations

import struct
from typing import Any

from dfa import IPv4HeaderDFA, TCPHeaderDFA


def normalize_hex_input(value: str | None) -> str:
    text = "" if value is None else str(value).strip()
    if text.lower().startswith("0x"):
        text = text[2:]

    return "".join(text.split())


def parse_ipv4_packet(
    packet: bytes | bytearray | None,
) -> dict[str, Any]:

    if packet is None or len(packet) == 0:
        return _error(
            "packet_length",
            "Empty packet input: no bytes were supplied.",
        )

    packet = bytes(packet)

    if len(packet) < 20:
        return _error(
            "packet_length",
            "Packet is shorter than the minimum IPv4 header length of 20 bytes.",
        )

    unpacked = struct.unpack("!BBHHHBBH4s4s", packet[:20])

    first_byte = unpacked[0]
    total_length = unpacked[2]
    ttl = unpacked[5]
    protocol = unpacked[6]

    fields = {
        "version": first_byte >> 4,
        "ihl": first_byte & 0x0F,
        "total_length": total_length,
        "ttl": ttl,
        "protocol": protocol,
        "protocol_name": {
            1: "ICMP",
            6: "TCP",
            17: "UDP",
        }.get(protocol, "Unknown"),
        "packet_size": len(packet),
    }

    result = IPv4HeaderDFA.validate_fields(
        fields,
        complete_packet=True,
    )

    if result.valid and protocol == 6:
        tcp_result = parse_tcp_header(
            packet,
            first_byte & 0x0F,
            total_length,
        )

        if not tcp_result["valid"]:
            return tcp_result

        result.parsed_fields["tcp"] = tcp_result["parsed_fields"]

    return {
        "valid": result.valid,
        "final_state": result.final_state,
        "failed_field": result.failed_field,
        "reason": result.reason,
        "parsed_fields": result.parsed_fields,
    }


def parse_tcp_header(
    packet: bytes,
    ihl: int,
    total_length: int,
) -> dict[str, Any]:
    """Parse and validate the TCP header following an IPv4 header."""

    header_start = ihl * 4
    segment_length = total_length - header_start

    if segment_length < 20 or len(packet) < header_start + 20:
        return _error(
            "tcp_header_length",
            "TCP header is shorter than the minimum 20 bytes.",
        )

    unpacked = struct.unpack(
        "!HHIIHHHH",
        packet[header_start:header_start + 20],
    )

    (
        source_port,
        destination_port,
        sequence_number,
        acknowledgement_number,
    ) = unpacked[:4]

    data_offset = unpacked[4] >> 12
    reserved = (unpacked[4] >> 9) & 0x07
    flags = unpacked[4] & 0x01FF

    tcp_header_length = data_offset * 4

    fields = {
        "source_port": source_port,
        "destination_port": destination_port,
        "sequence_number": sequence_number,
        "acknowledgement_number": acknowledgement_number,
        "data_offset": data_offset,
        "reserved": reserved,
        "flags": flags,
    }

    result = TCPHeaderDFA.validate_fields(fields)

    if result.valid and tcp_header_length > segment_length:
        return _error(
            "tcp_header_length",
            "TCP data offset exceeds the IPv4 payload length.",
        )

    return {
        "valid": result.valid,
        "final_state": result.final_state,
        "failed_field": result.failed_field,
        "reason": result.reason,
        "parsed_fields": result.parsed_fields,
    }


def parse_hex_packet(value: str | None) -> dict[str, Any]:
    text = normalize_hex_input(value)

    if not text:
        return _error(
            "hex_input",
            "Empty input: provide hexadecimal packet bytes.",
        )

    if len(text) % 2:
        return _error(
            "hex_input",
            "Odd-length hexadecimal input.",
        )

    if any(char not in "0123456789abcdefABCDEF" for char in text):
        return _error(
            "hex_input",
            "Invalid hexadecimal character found in packet input.",
        )

    try:
        return parse_ipv4_packet(bytes.fromhex(text))
    except ValueError:
        return _error(
            "hex_input",
            "Malformed hexadecimal input could not be converted to bytes.",
        )


def validate_manual_fields(fields: dict[str, Any]) -> dict[str, Any]:
    result = IPv4HeaderDFA.validate_fields(
        {
            name: fields.get(name)
            for name in (
                "version",
                "ihl",
                "total_length",
                "ttl",
                "protocol",
            )
        }
    )

    return result.__dict__


def _error(field: str, reason: str) -> dict[str, Any]:
    return {
        "valid": False,
        "final_state": "qR",
        "failed_field": field,
        "reason": reason,
        "parsed_fields": {},
    }
