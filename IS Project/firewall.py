import tkinter as tk
from tkinter import scrolledtext, messagebox
import threading
from pydivert import WinDivert

# ---------- Packet Capture and Filtering ----------
class Firewall:
    def __init__(self, log_callback):
        self.running = False
        self.log_callback = log_callback

    def start(self):
        self.running = True
        self.log_callback("Firewall started...")

        try:
            # Capture both inbound and outbound IPv4 packets
            with WinDivert("true") as w:
                for packet in w:
                    if not self.running:
                        break

                    # Display captured packet info
                    direction = "IN" if packet.is_inbound else "OUT"
                    info = f"[{direction}] {packet.src_addr} → {packet.dst_addr} | Protocol: {packet.protocol}"
                    self.log_callback(info)

                    # Apply filtering rule
                    if self.filter_packet(packet):
                        w.send(packet)
                    else:
                        self.log_callback(f"❌ Blocked: {packet.src_addr} → {packet.dst_addr}")

        except Exception as e:
            self.log_callback(f"Error: {e}")

    def stop(self):
        self.running = False
        self.log_callback("Firewall stopped.")

    def filter_packet(self, packet):
        # Example: Block traffic to Google's DNS (8.8.8.8)
        if packet.dst_addr == "8.8.8.8":
            return False
        return True


# ---------- GUI Frontend ----------
class FirewallGUI:
    def __init__(self, root):
        self.root = root
        self.root.title("Python Host-Based Firewall")
        self.root.geometry("700x450")

        self.text_area = scrolledtext.ScrolledText(root, width=85, height=20)
        self.text_area.pack(pady=10)

        self.start_btn = tk.Button(root, text="Start Firewall", command=self.start_firewall)
        self.start_btn.pack(side=tk.LEFT, padx=10)

        self.stop_btn = tk.Button(root, text="Stop Firewall", command=self.stop_firewall)
        self.stop_btn.pack(side=tk.LEFT, padx=10)

        self.firewall = Firewall(self.log_message)
        self.thread = None

    def log_message(self, message):
        self.text_area.insert(tk.END, message + "\n")
        self.text_area.see(tk.END)

    def start_firewall(self):
        if self.thread and self.thread.is_alive():
            messagebox.showinfo("Info", "Firewall already running.")
            return
        self.thread = threading.Thread(target=self.firewall.start, daemon=True)
        self.thread.start()

    def stop_firewall(self):
        self.firewall.stop()

# ---------- Main ----------
if __name__ == "__main__":
    root = tk.Tk()
    gui = FirewallGUI(root)
    root.mainloop()
