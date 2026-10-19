
def generate_packets():
    """Return valid and invalid packet samples for testing."""

    packets = [
        # 1. Valid TCP packet
        {
            "name": "valid_tcp",
            "ipv4": {
                "version": 4, "ihl": 5, "total_length": 40,
                "ttl": 64, "protocol": 6
            },
            "tcp": {
                "source_port": 12345, "destination_port": 80,
                "sequence_number": 1000, "acknowledgement_number": 0,
                "data_offset": 5, "reserved_bits": 0, "flags": 2
            },
            "valid": True
        },

        # 2. Valid UDP packet
        {
            "name": "valid_udp",
            "ipv4": {
                "version": 4, "ihl": 5, "total_length": 28,
                "ttl": 64, "protocol": 17
            },
            "udp": {
                "source_port": 12345, "destination_port": 53,
                "length": 8
            },
            "valid": True
        },

        # 3. TCP packet with payload
        {
            "name": "tcp_with_payload",
            "ipv4": {
                "version": 4, "ihl": 5, "total_length": 45,
                "ttl": 64, "protocol": 6
            },
            "tcp": {
                "source_port": 5000, "destination_port": 443,
                "sequence_number": 100, "acknowledgement_number": 200,
                "data_offset": 5, "reserved_bits": 0, "flags": 24
            },
            "payload": "hello",
            "valid": True
        },

        # 4. UDP packet with payload
        {
            "name": "udp_with_payload",
            "ipv4": {
                "version": 4, "ihl": 5, "total_length": 33,
                "ttl": 64, "protocol": 17
            },
            "udp": {
                "source_port": 5000, "destination_port": 5001,
                "length": 13
            },
            "payload": "hello",
            "valid": True
        },

        # 5. Invalid IPv4 version
        {
            "name": "invalid_ipv4_version",
            "ipv4": {
                "version": 6, "ihl": 5, "total_length": 40,
                "ttl": 64, "protocol": 6
            },
            "valid": False
        },

        # 6. Invalid IPv4 IHL
        {
            "name": "invalid_ihl",
            "ipv4": {
                "version": 4, "ihl": 4, "total_length": 40,
                "ttl": 64, "protocol": 6
            },
            "valid": False
        },

        # 7. Invalid IPv4 total length
        {
            "name": "invalid_total_length",
            "ipv4": {
                "version": 4, "ihl": 5, "total_length": 10,
                "ttl": 64, "protocol": 6
            },
            "valid": False
        },

        # 8. Invalid TCP data offset
        {
            "name": "invalid_tcp_data_offset",
            "ipv4": {
                "version": 4, "ihl": 5, "total_length": 40,
                "ttl": 64, "protocol": 6
            },
            "tcp": {
                "source_port": 12345, "destination_port": 80,
                "sequence_number": 100, "acknowledgement_number": 0,
                "data_offset": 4, "reserved_bits": 0, "flags": 2
            },
            "valid": False
        },

        # 9. Invalid TCP reserved bits
        {
            "name": "invalid_tcp_reserved_bits",
            "ipv4": {
                "version": 4, "ihl": 5, "total_length": 40,
                "ttl": 64, "protocol": 6
            },
            "tcp": {
                "source_port": 12345, "destination_port": 80,
                "sequence_number": 100, "acknowledgement_number": 0,
                "data_offset": 5, "reserved_bits": 1, "flags": 2
            },
            "valid": False
        },

        # 10. Invalid TCP flags
        {
            "name": "invalid_tcp_flags",
            "ipv4": {
                "version": 4, "ihl": 5, "total_length": 40,
                "ttl": 64, "protocol": 6
            },
            "tcp": {
                "source_port": 12345, "destination_port": 80,
                "sequence_number": 100, "acknowledgement_number": 0,
                "data_offset": 5, "reserved_bits": 0, "flags": 512
            },
            "valid": False
        },

        # 11. Invalid TTL
        {
            "name": "invalid_ttl",
            "ipv4": {
                "version": 4, "ihl": 5, "total_length": 40,
                "ttl": 0, "protocol": 6
            },
            "valid": False
        },

        # 12. Invalid TCP source port
        {
            "name": "invalid_tcp_source_port",
            "ipv4": {
                "version": 4, "ihl": 5, "total_length": 40,
                "ttl": 64, "protocol": 6
            },
            "tcp": {
                "source_port": 70000, "destination_port": 80,
                "sequence_number": 100, "acknowledgement_number": 0,
                "data_offset": 5, "reserved_bits": 0, "flags": 2
            },
            "valid": False
        },
    ]

    return packets


if __name__ == "__main__":
    samples = generate_packets()
    print(f"Generated {len(samples)} packet samples")

    for packet in samples:
        print(f"{packet['name']}: expected valid = {packet['valid']}")
