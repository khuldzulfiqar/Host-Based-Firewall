from pydivert import WinDivert
import threading
import time

class PacketCapture:
    def __init__(self, rule_engine, log_callback):
        self.rule_engine = rule_engine
        self.log_callback = log_callback
        self.running = False

    def start(self):
        self.running = True
        thread = threading.Thread(target=self.run, daemon=True)
        thread.start()

    def stop(self):
        self.running = False

    def run(self):
        # Capture all outbound TCP packets
        with WinDivert("outbound and tcp") as w:
            self.log_callback("Firewall started (capturing outbound TCP)...")
            for packet in w:
                if not self.running:
                    break

                proto = "tcp"
                packet.protocol = proto

                action = self.rule_engine.match_rule(packet)
                log_msg = f"{packet.src_addr}:{packet.src_port} → {packet.dst_addr}:{packet.dst_port} | {action.upper()}"

                if action == "block":
                    # Drop the packet (do not reinject)
                    self.log_callback(f"🚫 Blocked: {log_msg}")
                    continue
                else:
                    # Allow the packet
                    w.send(packet)
                    self.log_callback(f"✅ Allowed: {log_msg}")
