#!/usr/bin/env python3
"""
Simple test to show what the firewall should display
"""

import tkinter as tk
from tkinter import ttk, scrolledtext
import threading
import time
from datetime import datetime

class SimpleFirewallTest:
    def __init__(self):
        self.root = tk.Tk()
        self.root.title("🛡️ Firewall Test - What You Should See")
        self.root.geometry("800x600")
        
        self.create_gui()
        self.running = False
        
    def create_gui(self):
        """Create simple test GUI"""
        # Title
        title = tk.Label(self.root, text="🛡️ Firewall Test - What You Should See", 
                        font=("Arial", 14, "bold"))
        title.pack(pady=10)
        
        # Buttons
        button_frame = tk.Frame(self.root)
        button_frame.pack(pady=10)
        
        self.start_btn = tk.Button(button_frame, text="🚀 Start Test", 
                                  command=self.start_test, bg="green", fg="white")
        self.start_btn.pack(side=tk.LEFT, padx=5)
        
        self.stop_btn = tk.Button(button_frame, text="⏹️ Stop Test", 
                                 command=self.stop_test, bg="red", fg="white")
        self.stop_btn.pack(side=tk.LEFT, padx=5)
        
        # Activity Log
        log_label = tk.Label(self.root, text="Activity Log (What you should see):", 
                           font=("Arial", 12, "bold"))
        log_label.pack(anchor=tk.W, padx=10, pady=5)
        
        self.activity_log = scrolledtext.ScrolledText(self.root, height=15, width=80)
        self.activity_log.pack(fill=tk.BOTH, expand=True, padx=10, pady=5)
        
        # Instructions
        instructions = tk.Label(self.root, 
                              text="This shows you EXACTLY what your firewall should display when working correctly!",
                              font=("Arial", 10), fg="blue")
        instructions.pack(pady=5)
    
    def start_test(self):
        """Start the test"""
        self.running = True
        self.start_btn.config(state="disabled")
        
        # Start test in background
        self.test_thread = threading.Thread(target=self.run_test, daemon=True)
        self.test_thread.start()
    
    def stop_test(self):
        """Stop the test"""
        self.running = False
        self.start_btn.config(state="normal")
    
    def run_test(self):
        """Run the test simulation"""
        self.log("🛡️ Firewall started - monitoring network traffic...")
        time.sleep(1)
        
        # Simulate real firewall activity
        test_activities = [
            ("✅ ALLOWED: 192.168.1.100 → 8.8.8.8 (UDP:53) - DNS Query"),
            ("✅ ALLOWED: 192.168.1.100 → google.com (TCP:443) - HTTPS"),
            ("❌ BLOCKED: 192.168.1.100 → 10.0.0.1 (TCP:22) - Private Network"),
            ("✅ ALLOWED: 192.168.1.100 → youtube.com (TCP:80) - HTTP"),
            ("✅ ALLOWED: 192.168.1.100 → facebook.com (TCP:443) - HTTPS"),
            ("❌ BLOCKED: 192.168.1.100 → 192.168.1.1 (UDP:67) - DHCP to Router"),
            ("✅ ALLOWED: 192.168.1.100 → 8.8.8.8 (UDP:53) - DNS Query"),
            ("✅ ALLOWED: 192.168.1.100 → amazon.com (TCP:443) - HTTPS"),
            ("🔗 Connection: 192.168.1.100:1234 → 93.184.216.34:80 (TCP) - ESTABLISHED"),
            ("🔗 Connection: 192.168.1.100:1235 → 8.8.8.8:53 (UDP) - ESTABLISHED"),
            ("🔗 Connection: 192.168.1.100:1236 → google.com:443 (TCP) - ESTABLISHED"),
        ]
        
        for activity in test_activities:
            if not self.running:
                break
            self.log(activity)
            time.sleep(0.5)
        
        self.log("🛡️ Firewall test completed - this is what you should see!")
    
    def log(self, message):
        """Log message"""
        timestamp = datetime.now().strftime("%H:%M:%S")
        self.activity_log.insert(tk.END, f"[{timestamp}] {message}\n")
        self.activity_log.see(tk.END)
        self.root.update()
    
    def run(self):
        """Run the test"""
        self.root.mainloop()

if __name__ == "__main__":
    print("🛡️ Starting Firewall Test...")
    print("This shows you EXACTLY what your firewall should display!")
    print("\nWhat you should see:")
    print("1. ✅ ALLOWED packets (DNS, HTTP, HTTPS)")
    print("2. ❌ BLOCKED packets (Private networks)")
    print("3. 🔗 Active connections")
    print("4. Real IP addresses and protocols")
    print("\nClick 'Start Test' to see the simulation!")
    
    test = SimpleFirewallTest()
    test.run()
