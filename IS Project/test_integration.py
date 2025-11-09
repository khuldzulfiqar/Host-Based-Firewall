from packet_capture import PacketCapture
from rule_engine import RuleEngine, FirewallRule, RuleAction, RuleDirection, Protocol
from types import SimpleNamespace

def log(msg):
    print("[LOG]", msg)

# Initialize rule engine
engine = RuleEngine(log_callback=log)

# Add a rule to block outbound HTTP (port 80)
block_http = FirewallRule(
    name="Block HTTP Traffic",
    action=RuleAction.DENY,
    direction=RuleDirection.OUTBOUND,
    protocol=Protocol.TCP,
    dst_port=80,
    description="Block all HTTP traffic"
)
engine.add_rule(block_http)

# Initialize capture
capture = PacketCapture(log_callback=print)


def processor(packet):
    allowed, rule = engine.evaluate_packet(SimpleNamespace(
        src_ip=packet.src_ip,
        dst_ip=packet.dst_ip,
        src_port=packet.src_port,
        dst_port=packet.dst_port,
        protocol=packet.protocol,
        direction=packet.direction  # ✅ FIXED LINE (removed .name)
    ))

    if not allowed:
        print(f"🚫 Blocked packet: {packet.src_ip} → {packet.dst_ip} | Port {packet.dst_port}")
    else:
        print(f"✅ Allowed packet: {packet.src_ip} → {packet.dst_ip} | Port {packet.dst_port}")

# Start capture with rule processing
print("Starting live test (press Ctrl + C to stop)...\n")
capture.start_capture(packet_processor=processor)
