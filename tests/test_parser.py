import unittest
from packet_generator import generate_packets


class TestPacketGenerator(unittest.TestCase):

    def test_generates_at_least_10_packets(self):
        self.assertGreaterEqual(len(generate_packets()), 10)

    def test_every_packet_has_required_fields(self):
        for packet in generate_packets():
            with self.subTest(packet=packet["name"]):
                self.assertIn("name", packet)
                self.assertIn("ipv4", packet)
                self.assertIn("valid", packet)

    def test_contains_valid_and_invalid_packets(self):
        results = {packet["valid"] for packet in generate_packets()}
        self.assertIn(True, results)
        self.assertIn(False, results)

    def test_packet_names_are_unique(self):
        names = [packet["name"] for packet in generate_packets()]
        self.assertEqual(len(names), len(set(names)))


if __name__ == "__main__":
    unittest.main()
