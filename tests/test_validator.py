import unittest
from packet_generator import generate_packets


class TestPacketValidationSamples(unittest.TestCase):

    def test_valid_samples_exist(self):
        packets = generate_packets()
        valid_packets = [p for p in packets if p["valid"]]
        self.assertGreaterEqual(len(valid_packets), 1)

    def test_invalid_samples_exist(self):
        packets = generate_packets()
        invalid_packets = [p for p in packets if not p["valid"]]
        self.assertGreaterEqual(len(invalid_packets), 1)

    def test_required_invalid_cases_exist(self):
        names = {p["name"] for p in generate_packets()}
        required = {
            "invalid_ipv4_version",
            "invalid_ihl",
            "invalid_total_length",
            "invalid_tcp_data_offset",
            "invalid_tcp_reserved_bits",
            "invalid_tcp_flags",
            "invalid_ttl",
        }
        self.assertTrue(required.issubset(names))


if __name__ == "__main__":
    unittest.main()
