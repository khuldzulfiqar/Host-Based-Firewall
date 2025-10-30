from rule_engine import RuleEngine, RuleAction
from types import SimpleNamespace

# Logger to print rule matches
def logger(msg):
    print(msg)

# Initialize rule engine with logger
engine = RuleEngine(log_callback=logger)
engine.set_default_action(RuleAction.DENY)

# Helper function to test a packet
def test_packet(packet, expected_action):
    result, matched_rule = engine.evaluate_packet(packet)
    print(f"Packet: {packet}")
    print(f"Expected: {expected_action}, Got: {'ALLOW' if result else 'DENY'}")
    print(f"Matched Rule: {matched_rule.name if matched_rule else 'None'}")
    print("-" * 50)

# Test 1: HTTPS outbound
packet1 = SimpleNamespace(
    src_ip="192.168.0.73", dst_ip="142.250.187.3",
    src_port=50000, dst_port=443, protocol="TCP", direction="OUT"
)
test_packet(packet1, "ALLOW")

# Test 2: HTTP outbound
packet2 = SimpleNamespace(
    src_ip="192.168.0.73", dst_ip="93.184.216.34",
    src_port=50001, dst_port=80, protocol="TCP", direction="OUT"
)
test_packet(packet2, "ALLOW")

# Test 3: DNS query
packet3 = SimpleNamespace(
    src_ip="192.168.0.73", dst_ip="8.8.8.8",
    src_port=50002, dst_port=53, protocol="UDP", direction="OUT"
)
test_packet(packet3, "ALLOW")

# Test 4: Private network outbound (should be blocked)
packet4 = SimpleNamespace(
    src_ip="192.168.0.73", dst_ip="10.1.2.3",
    src_port=50003, dst_port=443, protocol="TCP", direction="OUT"
)
test_packet(packet4, "DENY")

# Test 5: LAN traffic (allowed)
packet5 = SimpleNamespace(
    src_ip="192.168.0.73", dst_ip="192.168.0.100",
    src_port=50004, dst_port=22, protocol="TCP", direction="OUT"
)
test_packet(packet5, "ALLOW")

# Test 6: RDP inbound (should be blocked)
packet6 = SimpleNamespace(
    src_ip="203.0.113.5", dst_ip="192.168.0.73",
    src_port=50005, dst_port=3389, protocol="TCP", direction="IN"
)
test_packet(packet6, "DENY")

# Test 7: VPN traffic (allowed)
packet7 = SimpleNamespace(
    src_ip="192.168.0.73", dst_ip="198.51.100.10",
    src_port=50006, dst_port=1194, protocol="UDP", direction="OUT"
)
test_packet(packet7, "ALLOW")

# Test 8: Unknown TCP traffic (should log)
packet8 = SimpleNamespace(
    src_ip="192.168.0.73", dst_ip="203.0.113.20",
    src_port=50007, dst_port=5555, protocol="TCP", direction="OUT"
)
test_packet(packet8, "ALLOW")  # default_action is ALLOW, but LOG rule triggers
