"""Interactive entry point for the IPv4 packet header validator."""

from __future__ import annotations

from parser import parse_hex_packet, validate_manual_fields


def show_result(result: dict[str, object]) -> None:
    parsed_fields = result.get("parsed_fields")
    protocol_name = "Unknown"

    if isinstance(parsed_fields, dict):
        protocol_name = str(parsed_fields.get("protocol_name", "Unknown"))
        if protocol_name == "Unknown":
            try:
                protocol_name = {
                    1: "ICMP",
                    6: "TCP",
                    17: "UDP",
                }.get(int(parsed_fields.get("protocol")), "Unknown")
            except (TypeError, ValueError):
                pass

    if result["valid"]:
        print("\nVALID")
        print(f"Final state: {result.get('final_state')}")
        print(f"Protocol name: {protocol_name}")
        print(f"Reason: {result.get('reason')}")
    else:
        print("\nINVALID")
        print(f"Rejected field: {result.get('failed_field')}")
        print(f"Reason: {result.get('reason')}")
        print(f"Final state: {result.get('final_state')}")


def manual_validation() -> None:
    fields: dict[str, str] = {}
    for name in ("version", "ihl", "total_length", "ttl", "protocol"):
        fields[name] = input(f"{name}: ").strip()
    show_result(validate_manual_fields(fields))


def raw_validation() -> None:
    print("Whitespace and an optional 0x prefix are accepted.")
    show_result(parse_hex_packet(input("Packet hex: ")))


def main() -> None:
    while True:
        print("\nNetwork Packet Header Validator")
        print("1. Enter IPv4 header fields manually")
        print("2. Validate a raw IPv4 packet in hexadecimal")
        print("3. Run predefined test cases")
        print("4. Generate sample packets using Scapy")
        print("5. Display DFA states and transition table")
        print("6. Exit")
        choice = input("Enter your choice: ").strip()

        if choice == "1":
            manual_validation()
        elif choice == "2":
            raw_validation()
        elif choice == "3":
            import unittest

            suite = unittest.defaultTestLoader.discover("tests")
            unittest.TextTestRunner(verbosity=2).run(suite)
        elif choice == "4":
            from packet_generator import generate_samples

            try:
                for name, packet in generate_samples().items():
                    print(f"{name}: {packet.hex()}")
            except RuntimeError as exc:
                print(exc)
        elif choice == "5":
            from dfa import IPv4HeaderDFA, TCPHeaderDFA

            print("Q =", set(IPv4HeaderDFA.states))
            print("Sigma = {PASS, FAIL}; q0 = START; F = {qA}")
            for transition in IPv4HeaderDFA.transition_table():
                print(transition)

            print("\nTCP DFA")
            print("T =", set(TCPHeaderDFA.states))
            print("Sigma = {PASS, FAIL}; t0 = START; F = {tA}")
            for transition in TCPHeaderDFA.transition_table():
                print(transition)
        elif choice == "6":
            print("Exiting.")
            return
        else:
            print("Choose an option from 1 to 6.")


if __name__ == "__main__":
    main()