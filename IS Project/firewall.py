import tkinter as tk
from tkinter import scrolledtext, messagebox, ttk
import threading
import time
from datetime import datetime

# Import all modules
from packet_capture import PacketCapture, PacketInfo
from rule_engine import RuleEngine, RuleAction, RuleDirection, Protocol, FirewallRule
from stateful_inspection import StatefulInspector, ConnectionState
from rule_management import RuleManager
from logging_monitoring import FirewallLogger, FirewallMonitor, LogLevel, FirewallEvent
from configuration_policy import ConfigurationManager, PolicyManager

# ---------- Enhanced Firewall with All Modules ----------
class EnhancedFirewall:
    def __init__(self, log_callback):
        self.running = False
        self.log_callback = log_callback
        
        # Initialize all modules
        self.packet_capture = PacketCapture(self.log_callback)
        self.rule_engine = RuleEngine(self.log_callback)
        self.stateful_inspector = StatefulInspector(self.log_callback)
        self.rule_manager = RuleManager(self.rule_engine)
        self.logger = FirewallLogger()
        self.monitor = FirewallMonitor(self.logger)
        self.config_manager = ConfigurationManager()
        self.policy_manager = PolicyManager()
        
        # Statistics
        self.stats = {
            'packets_processed': 0,
            'packets_blocked': 0,
            'packets_allowed': 0,
            'connections_tracked': 0,
            'rules_evaluated': 0
        }

    def start(self):
        """Start the enhanced firewall"""
        self.running = True
        self.log_callback("Enhanced Firewall started...")
        
        # Start monitoring
        self.monitor.start_monitoring()
        
        # Install demo/blocking rules for verification (only once per run)
        try:
            self._install_demo_rules()
        except Exception as e:
            self.log_callback(f"Rule setup error: {e}")
        
        # Start packet capture in a separate thread with packet processor
        self.capture_thread = threading.Thread(
            target=self._start_packet_capture_with_processing, 
            daemon=True
        )
        self.capture_thread.start()
        
        # Log startup
        self.logger.log_event(FirewallEvent(
            timestamp=datetime.now(),
            event_type="FIREWALL_STARTED",
            level=LogLevel.INFO,
            message="Enhanced Firewall started successfully"
        ))
    
    def _start_packet_capture_with_processing(self):
        """Start packet capture with integrated processing"""
        try:
            from pydivert import WinDivert
            
            self.log_callback("Starting packet capture with processing...")
            
            # Focus on IPv4 TCP/UDP so connections display and noise is reduced
            with WinDivert("ip and (tcp or udp)") as w:
                for packet in w:
                    if not self.running:
                        break
                    
                    # Parse packet
                    packet_info = self.packet_capture._parse_packet(packet)
                    self.packet_capture._update_stats(packet_info)
                    self.packet_capture.captured_packets.append(packet_info)
                    
                    # Process through firewall
                    should_allow = self.process_packet(packet_info)
                    
                    # Send or drop packet based on decision
                    if should_allow:
                        w.send(packet)
                        self.log_callback(f"✅ ALLOWED: {packet_info.src_ip} → {packet_info.dst_ip} ({packet_info.protocol})")
                    else:
                        self.log_callback(f"❌ BLOCKED: {packet_info.src_ip} → {packet_info.dst_ip} ({packet_info.protocol})")
                    
        except Exception as e:
            self.log_callback(f"Packet capture error: {e}")

    def _install_demo_rules(self):
        """Install quick demo rules so user can immediately verify blocking."""
        # If rules already include our demo rules, skip
        existing = [r.name for r in self.rule_engine.get_all_rules()]
        
        # Highest priority first (lower number == higher priority)
        if "Block 8.8.8.8" not in existing:
            self.rule_engine.add_rule(FirewallRule(
                id="demo_block_8888",
                name="Block 8.8.8.8",
                action=RuleAction.DENY,
                direction=RuleDirection.OUTBOUND,
                protocol=Protocol.ANY,
                dst_ip="8.8.8.8",
                priority=1,
                description="Demo: Block outbound traffic to Google DNS"
            ))
        
        if "Block HTTP Port 80" not in existing:
            self.rule_engine.add_rule(FirewallRule(
                id="demo_block_http80",
                name="Block HTTP Port 80",
                action=RuleAction.DENY,
                direction=RuleDirection.OUTBOUND,
                protocol=Protocol.TCP,
                dst_port=80,
                priority=2,
                description="Demo: Block outbound HTTP so you can verify blocking"
            ))

    def stop(self):
        """Stop the enhanced firewall"""
        self.running = False
        self.packet_capture.stop_capture()
        self.monitor.stop_monitoring()
        self.stateful_inspector.stop()
        self.logger.stop()
        
        # Wait for capture thread to finish
        if hasattr(self, 'capture_thread') and self.capture_thread and self.capture_thread.is_alive():
            self.capture_thread.join(timeout=2)
        
        self.log_callback("Enhanced Firewall stopped.")
        
        # Log shutdown
        self.logger.log_event(FirewallEvent(
            timestamp=datetime.now(),
            event_type="FIREWALL_STOPPED",
            level=LogLevel.INFO,
            message="Enhanced Firewall stopped"
        ))

    def process_packet(self, packet_info: PacketInfo) -> bool:
        """Process a packet through all modules"""
        try:
            self.stats['packets_processed'] += 1
            
            # Stateful inspection
            should_allow, connection_state, connection = self.stateful_inspector.inspect_packet(packet_info)
            
            if connection:
                self.stats['connections_tracked'] += 1
            
            # Rule engine evaluation
            rule_allow, matching_rule = self.rule_engine.evaluate_packet(packet_info)
            self.stats['rules_evaluated'] += 1
            
            # Policy evaluation
            policy_actions = self.policy_manager.evaluate_policies(packet_info)
            
            # Final decision
            final_decision = should_allow and rule_allow
            
            # Log the decision
            if final_decision:
                self.stats['packets_allowed'] += 1
                self.logger.log_packet_allowed(
                    packet_info.src_ip, packet_info.dst_ip, packet_info.protocol,
                    matching_rule.id if matching_rule else None
                )
            else:
                self.stats['packets_blocked'] += 1
                self.logger.log_packet_blocked(
                    packet_info.src_ip, packet_info.dst_ip, packet_info.protocol,
                    "Rule match" if matching_rule else "Default policy",
                    matching_rule.id if matching_rule else None
                )
            
            return final_decision
            
        except Exception as e:
            self.log_callback(f"Error processing packet: {e}")
            self.logger.log_security_alert(f"Packet processing error: {e}")
            return False

    def get_statistics(self):
        """Get firewall statistics"""
        return {
            'firewall_stats': self.stats,
            'capture_stats': self.packet_capture.get_stats(),
            'rule_stats': self.rule_engine.get_rule_statistics(),
            'connection_stats': self.stateful_inspector.get_connection_statistics(),
            'log_stats': self.logger.get_statistics(),
            'monitor_stats': self.monitor.get_metrics()
        }


# ---------- Enhanced GUI Frontend ----------
class EnhancedFirewallGUI:
    def __init__(self, root):
        self.root = root
        self.root.title("Enhanced Host-Based Firewall")
        self.root.geometry("1200x800")

        # Initialize firewall first
        self.firewall = EnhancedFirewall(self.log_message)
        self.thread = None
        self.capture_thread = None

        # Create notebook for tabs
        self.notebook = ttk.Notebook(root)
        self.notebook.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)

        # Create tabs
        self._create_dashboard_tab()
        self._create_rules_tab()
        self._create_monitoring_tab()
        self._create_logs_tab()
        self._create_configuration_tab()

    def _create_dashboard_tab(self):
        """Create main dashboard tab"""
        dashboard_frame = ttk.Frame(self.notebook)
        self.notebook.add(dashboard_frame, text="Dashboard")

        # Control buttons
        control_frame = ttk.Frame(dashboard_frame)
        control_frame.pack(fill=tk.X, padx=10, pady=10)

        self.start_btn = ttk.Button(control_frame, text="Start Firewall", command=self.start_firewall)
        self.start_btn.pack(side=tk.LEFT, padx=5)

        self.stop_btn = ttk.Button(control_frame, text="Stop Firewall", command=self.stop_firewall)
        self.stop_btn.pack(side=tk.LEFT, padx=5)

        self.stats_btn = ttk.Button(control_frame, text="Refresh Stats", command=self.refresh_stats)
        self.stats_btn.pack(side=tk.LEFT, padx=5)

        # Status display
        status_frame = ttk.LabelFrame(dashboard_frame, text="Status")
        status_frame.pack(fill=tk.X, padx=10, pady=5)

        self.status_label = ttk.Label(status_frame, text="Firewall: Stopped", font=("Arial", 12, "bold"))
        self.status_label.pack(pady=5)

        # Statistics display
        stats_frame = ttk.LabelFrame(dashboard_frame, text="Statistics")
        stats_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=5)

        self.stats_text = scrolledtext.ScrolledText(stats_frame, height=15, width=80)
        self.stats_text.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)

        # Activity log
        log_frame = ttk.LabelFrame(dashboard_frame, text="Activity Log")
        log_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=5)

        self.log_text = scrolledtext.ScrolledText(log_frame, height=10, width=80)
        self.log_text.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)

    def _create_rules_tab(self):
        """Create rules management tab"""
        rules_frame = ttk.Frame(self.notebook)
        self.notebook.add(rules_frame, text="Rules")

        # Create rule management GUI
        self.rule_manager_gui = self.firewall.rule_manager.show_gui(rules_frame)

    def _create_monitoring_tab(self):
        """Create monitoring tab"""
        monitor_frame = ttk.Frame(self.notebook)
        self.notebook.add(monitor_frame, text="Monitoring")

        # Real-time metrics
        metrics_frame = ttk.LabelFrame(monitor_frame, text="Real-time Metrics")
        metrics_frame.pack(fill=tk.X, padx=10, pady=5)

        self.metrics_text = scrolledtext.ScrolledText(metrics_frame, height=10, width=80)
        self.metrics_text.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)

        # Connection monitoring
        conn_frame = ttk.LabelFrame(monitor_frame, text="Active Connections")
        conn_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=5)

        self.connections_text = scrolledtext.ScrolledText(conn_frame, height=15, width=80)
        self.connections_text.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)

        # Refresh button
        ttk.Button(monitor_frame, text="Refresh Monitoring", command=self.refresh_monitoring).pack(pady=5)

    def _create_logs_tab(self):
        """Create logs tab"""
        logs_frame = ttk.Frame(self.notebook)
        self.notebook.add(logs_frame, text="Logs")

        # Log display
        self.logs_text = scrolledtext.ScrolledText(logs_frame, height=25, width=100)
        self.logs_text.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)

        # Log controls
        log_controls = ttk.Frame(logs_frame)
        log_controls.pack(fill=tk.X, padx=10, pady=5)

        ttk.Button(log_controls, text="Refresh Logs", command=self.refresh_logs).pack(side=tk.LEFT, padx=5)
        ttk.Button(log_controls, text="Clear Logs", command=self.clear_logs).pack(side=tk.LEFT, padx=5)
        ttk.Button(log_controls, text="Export Logs", command=self.export_logs).pack(side=tk.LEFT, padx=5)

    def _create_configuration_tab(self):
        """Create configuration tab"""
        config_frame = ttk.Frame(self.notebook)
        self.notebook.add(config_frame, text="Configuration")

        # Configuration management
        from configuration_policy import ConfigurationGUI
        self.config_gui = ConfigurationGUI(config_frame, 
                                         self.firewall.config_manager, 
                                         self.firewall.policy_manager)

    def log_message(self, message):
        """Log message to activity log"""
        timestamp = datetime.now().strftime("%H:%M:%S")
        # Check if log_text widget exists before trying to use it
        if hasattr(self, 'log_text') and self.log_text:
            self.log_text.insert(tk.END, f"[{timestamp}] {message}\n")
            self.log_text.see(tk.END)
        else:
            # Fallback to console output during initialization
            print(f"[{timestamp}] {message}")

    def start_firewall(self):
        """Start the firewall"""
        if self.thread and self.thread.is_alive():
            messagebox.showinfo("Info", "Firewall already running.")
            return
        
        # Start firewall in a separate thread
        self.thread = threading.Thread(target=self.firewall.start, daemon=True)
        self.thread.start()
        self.status_label.config(text="Firewall: Running", foreground="green")

    def stop_firewall(self):
        """Stop the firewall"""
        self.firewall.stop()
        self.status_label.config(text="Firewall: Stopped", foreground="red")

    def refresh_stats(self):
        """Refresh statistics display"""
        try:
            stats = self.firewall.get_statistics()
            
            self.stats_text.delete(1.0, tk.END)
            self.stats_text.insert(tk.END, "=== FIREWALL STATISTICS ===\n\n")
            
            # Firewall stats
            self.stats_text.insert(tk.END, "Firewall Statistics:\n")
            for key, value in stats['firewall_stats'].items():
                self.stats_text.insert(tk.END, f"  {key}: {value}\n")
            
            # Capture stats
            self.stats_text.insert(tk.END, "\nPacket Capture Statistics:\n")
            for key, value in stats['capture_stats'].items():
                self.stats_text.insert(tk.END, f"  {key}: {value}\n")
            
            # Rule stats
            self.stats_text.insert(tk.END, "\nRule Engine Statistics:\n")
            for key, value in stats['rule_stats'].items():
                self.stats_text.insert(tk.END, f"  {key}: {value}\n")
            
            # Connection stats
            self.stats_text.insert(tk.END, "\nConnection Statistics:\n")
            for key, value in stats['connection_stats'].items():
                self.stats_text.insert(tk.END, f"  {key}: {value}\n")
            
            # Log stats
            self.stats_text.insert(tk.END, "\nLogging Statistics:\n")
            for key, value in stats['log_stats'].items():
                self.stats_text.insert(tk.END, f"  {key}: {value}\n")
            
            # Monitor stats
            self.stats_text.insert(tk.END, "\nMonitoring Statistics:\n")
            for key, value in stats['monitor_stats'].items():
                self.stats_text.insert(tk.END, f"  {key}: {value}\n")
            
            # Add timestamp
            from datetime import datetime
            timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            self.stats_text.insert(tk.END, f"\n\nLast updated: {timestamp}\n")
                
        except Exception as e:
            self.log_message(f"Error refreshing stats: {e}")
            # Show error in stats
            self.stats_text.delete(1.0, tk.END)
            self.stats_text.insert(tk.END, f"Error loading statistics: {e}\n")
            self.stats_text.insert(tk.END, "Make sure the firewall is running and try again.")

    def refresh_monitoring(self):
        """Refresh monitoring display"""
        try:
            # Get metrics
            metrics = self.firewall.monitor.get_metrics()
            
            self.metrics_text.delete(1.0, tk.END)
            self.metrics_text.insert(tk.END, "=== REAL-TIME METRICS ===\n\n")
            
            for key, value in metrics.items():
                self.metrics_text.insert(tk.END, f"{key}: {value}\n")
            
            # Get connections
            connections = self.firewall.stateful_inspector.get_all_connections()
            
            self.connections_text.delete(1.0, tk.END)
            self.connections_text.insert(tk.END, "=== ACTIVE CONNECTIONS ===\n\n")
            
            if connections:
                for conn in connections[-20:]:  # Show last 20 connections
                    self.connections_text.insert(tk.END, 
                        f"{conn.src_ip}:{conn.src_port} -> {conn.dst_ip}:{conn.dst_port} "
                        f"({conn.protocol}) - {conn.state.value}\n"
                    )
            else:
                # Show some sample connections if none exist
                self.connections_text.insert(tk.END, "No active connections found.\n\n")
                self.connections_text.insert(tk.END, "To see connections:\n")
                self.connections_text.insert(tk.END, "1. Start the firewall\n")
                self.connections_text.insert(tk.END, "2. Open web browser and visit websites\n")
                self.connections_text.insert(tk.END, "3. Run 'ping google.com' in command prompt\n")
                self.connections_text.insert(tk.END, "4. Refresh this page\n\n")
                self.connections_text.insert(tk.END, "Sample connections you should see:\n")
                self.connections_text.insert(tk.END, "192.168.1.100:1234 -> 8.8.8.8:53 (UDP) - ESTABLISHED\n")
                self.connections_text.insert(tk.END, "192.168.1.100:1235 -> google.com:443 (TCP) - ESTABLISHED\n")
                self.connections_text.insert(tk.END, "192.168.1.100:1236 -> youtube.com:80 (TCP) - ESTABLISHED\n")
                
        except Exception as e:
            self.log_message(f"Error refreshing monitoring: {e}")
            # Show error in connections
            self.connections_text.delete(1.0, tk.END)
            self.connections_text.insert(tk.END, f"Error loading connections: {e}\n")
            self.connections_text.insert(tk.END, "Make sure the firewall is running and try again.")

    def refresh_logs(self):
        """Refresh logs display"""
        try:
            # Get recent events
            events = self.firewall.logger.get_recent_events(100)
            
            self.logs_text.delete(1.0, tk.END)
            self.logs_text.insert(tk.END, "=== RECENT LOG EVENTS ===\n\n")
            
            if events:
                for event in events:
                    timestamp = event.timestamp.strftime("%Y-%m-%d %H:%M:%S")
                    self.logs_text.insert(tk.END, f"[{timestamp}] {event.level} - {event.message}\n")
            else:
                # Show activity log content if no events
                self.logs_text.insert(tk.END, "No log events found. Showing activity log:\n\n")
                activity_content = self.log_text.get(1.0, tk.END)
                if activity_content.strip():
                    self.logs_text.insert(tk.END, activity_content)
                else:
                    self.logs_text.insert(tk.END, "No activity logged yet. Start the firewall and generate network traffic.\n")
                
        except Exception as e:
            self.log_message(f"Error refreshing logs: {e}")
            # Show error in logs
            self.logs_text.delete(1.0, tk.END)
            self.logs_text.insert(tk.END, f"Error loading logs: {e}\n")
            self.logs_text.insert(tk.END, "Make sure the firewall is running and try again.")

    def clear_logs(self):
        """Clear logs display"""
        self.logs_text.delete(1.0, tk.END)

    def export_logs(self):
        """Export logs to file"""
        try:
            from tkinter import filedialog
            filename = filedialog.asksaveasfilename(
                defaultextension=".txt",
                filetypes=[("Text files", "*.txt"), ("All files", "*.*")]
            )
            if filename:
                with open(filename, 'w') as f:
                    f.write(self.logs_text.get(1.0, tk.END))
                messagebox.showinfo("Success", f"Logs exported to {filename}")
        except Exception as e:
            messagebox.showerror("Error", f"Error exporting logs: {e}")

# ---------- Main ----------
if __name__ == "__main__":
    root = tk.Tk()
    gui = EnhancedFirewallGUI(root)
    try:
     root.mainloop()
    except KeyboardInterrupt:
     print("Firewall stopped by user.")
