"""
Test Script for RuleEngine
Tests all default firewall rules using mock packets
"""

from rule_engine import RuleEngine, RuleAction

# Mock Packet class
class TestPacket:
    def __init__(self, src_ip, dst_ip, protocol, direction, src_port=None, dst_port=None):
        self.src_ip = src_ip
        self.dst_ip = dst_ip
        self.protocol = protocol  # "TCP", "UDP", "ICMP", etc.
        self.direction = direction  # "IN" or "OUT"
        self.src_port = src_port
        self.dst_port = dst_port

# Log callback to display matches
def log(msg):
    print(msg)

# Initialize RuleEngine with log
engine = RuleEngine(log_callback=log)

# Test Cases
test_packets = [
    # LAN traffic (should be allowed)
    TestPacket("192.168.0.10", "192.168.0.20", "TCP", "OUT"),
    
    # Block RDP inbound
    TestPacket("8.8.8.8", "192.168.0.73", "TCP", "IN", dst_port=3389),
    
    # Allow HTTPS outbound
    TestPacket("192.168.0.73", "142.250.187.3", "TCP", "OUT", dst_port=443),
    
    # Allow HTTP outbound
    TestPacket("192.168.0.73", "93.184.216.34", "TCP", "OUT", dst_port=80),
    
    # Allow DNS queries
    TestPacket("192.168.0.73", "8.8.8.8", "UDP", "OUT", dst_port=53),
    
    # Allow VPN traffic
    TestPacket("192.168.0.73", "1.2.3.4", "UDP", "OUT", dst_port=1194),
    
    # Unknown TCP traffic (should be logged)
    TestPacket("192.168.0.73", "8.8.8.8", "TCP", "OUT", dst_port=5000),
    
    # Private network outbound (should be denied)
    TestPacket("192.168.0.73", "10.1.2.3", "TCP", "OUT", dst_port=443),
    
    # Incoming HTTPS response
    TestPacket("142.250.187.3", "192.168.0.73", "TCP", "IN", src_port=443),
    
    # Incoming HTTP response
    TestPacket("93.184.216.34", "192.168.0.73", "TCP", "IN", src_port=80),
]

# Run tests
print("\n=== Firewall Rule Engine Test Results ===\n")
for i, pkt in enumerate(test_packets, 1):
    allowed, rule = engine.evaluate_packet(pkt)
    print(f"Test {i}: {pkt.direction} {pkt.protocol} {pkt.src_ip}:{pkt.src_port} -> {pkt.dst_ip}:{pkt.dst_port}")
    print(f"Result: {'ALLOWED' if allowed else 'BLOCKED'}, Matched Rule: {rule.name if rule else 'None'}\n")
