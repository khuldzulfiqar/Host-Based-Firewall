"""
Configuration & Policy Module
Configuration management and policy enforcement system
"""

import json
import os
import tkinter as tk
from tkinter import ttk
from tkinter import messagebox
from tkinter import simpledialog
from typing import Dict, List, Any, Optional, Union

# Optional YAML import
try:
    import yaml
    YAML_AVAILABLE = True
except ImportError:
    YAML_AVAILABLE = False
from dataclasses import dataclass, asdict
from datetime import datetime
from enum import Enum
import threading

class PolicyType(Enum):
    SECURITY = "SECURITY"
    NETWORK = "NETWORK"
    PERFORMANCE = "PERFORMANCE"
    COMPLIANCE = "COMPLIANCE"

class PolicyAction(Enum):
    ALLOW = "ALLOW"
    DENY = "DENY"
    LOG = "LOG"
    ALERT = "ALERT"
    QUARANTINE = "QUARANTINE"

@dataclass
class Policy:
    """Represents a security policy"""
    id: str
    name: str
    policy_type: PolicyType
    description: str
    rules: List[Dict[str, Any]]
    conditions: List[Dict[str, Any]]
    actions: List[PolicyAction]
    priority: int
    enabled: bool
    created_at: datetime
    updated_at: datetime
    expires_at: Optional[datetime] = None

@dataclass
class FirewallConfig:
    """Firewall configuration settings"""
    # General settings
    firewall_enabled: bool = True
    default_action: str = "ALLOW"
    log_level: str = "INFO"
    max_connections: int = 1000
    connection_timeout: int = 300
    
    # Security settings
    enable_stateful_inspection: bool = True
    enable_intrusion_detection: bool = True
    enable_dos_protection: bool = True
    max_packets_per_second: int = 10000
    
    # Logging settings
    log_packets: bool = True
    log_connections: bool = True
    log_security_events: bool = True
    log_retention_days: int = 30
    
    # Performance settings
    packet_buffer_size: int = 1000
    rule_evaluation_timeout: float = 0.1
    cleanup_interval: int = 60
    
    # Network settings
    trusted_networks: List[str] = None
    blocked_networks: List[str] = None
    allowed_ports: List[int] = None
    blocked_ports: List[int] = None
    # Feature flags
    enable_demo_rules: bool = False
    
    def __post_init__(self):
        if self.trusted_networks is None:
            self.trusted_networks = []
        if self.blocked_networks is None:
            self.blocked_networks = []
        if self.allowed_ports is None:
            self.allowed_ports = [80, 443, 53]
        if self.blocked_ports is None:
            self.blocked_ports = []

class ConfigurationManager:
    """Manages firewall configuration"""
    
    def __init__(self, config_file: str = "firewall_config.json"):
        base_dir = os.path.dirname(__file__)
        self.config_file = os.path.join(base_dir, config_file)
        self.config = FirewallConfig()
        self.policies: List[Policy] = []
        # Use re-entrant lock to avoid deadlock when save is called from update
        self.config_lock = threading.RLock()
        
        # Load configuration
        self.load_configuration()
    
    def load_configuration(self) -> bool:
        """Load configuration from file"""
        try:
            if os.path.exists(self.config_file):
                with open(self.config_file, 'r') as f:
                    config_data = json.load(f)
                
                # Update configuration
                for key, value in config_data.items():
                    if hasattr(self.config, key):
                        setattr(self.config, key, value)
                
                return True
            else:
                # Create default configuration
                self.save_configuration()
                return True
        except Exception as e:
            print(f"Error loading configuration: {e}")
            return False
    
    def save_configuration(self) -> bool:
        """Save configuration to file"""
        try:
            with self.config_lock:
                config_dict = asdict(self.config)
                with open(self.config_file, 'w') as f:
                    json.dump(config_dict, f, indent=2, default=str)
                return True
        except Exception as e:
            print(f"Error saving configuration: {e}")
            return False
    
    def get_config(self) -> FirewallConfig:
        """Get current configuration"""
        with self.config_lock:
            return self.config
    
    def update_config(self, **kwargs) -> bool:
        """Update configuration settings"""
        try:
            with self.config_lock:
                for key, value in kwargs.items():
                    if hasattr(self.config, key):
                        setattr(self.config, key, value)
                return self.save_configuration()
        except Exception as e:
            print(f"Error updating configuration: {e}")
            return False
    
    def reset_to_defaults(self) -> bool:
        """Reset configuration to defaults"""
        try:
            self.config = FirewallConfig()
            return self.save_configuration()
        except Exception as e:
            print(f"Error resetting configuration: {e}")
            return False
    
    def export_configuration(self, filename: str) -> bool:
        """Export configuration to file"""
        try:
            config_dict = asdict(self.config)
            with open(filename, 'w') as f:
                json.dump(config_dict, f, indent=2, default=str)
            return True
        except Exception as e:
            print(f"Error exporting configuration: {e}")
            return False
    
    def import_configuration(self, filename: str) -> bool:
        """Import configuration from file"""
        try:
            with open(filename, 'r') as f:
                config_data = json.load(f)
            
            # Validate configuration
            if self._validate_config(config_data):
                for key, value in config_data.items():
                    if hasattr(self.config, key):
                        setattr(self.config, key, value)
                return self.save_configuration()
            return False
        except Exception as e:
            print(f"Error importing configuration: {e}")
            return False
    
    def _validate_config(self, config_data: Dict[str, Any]) -> bool:
        """Validate configuration data"""
        required_fields = ['firewall_enabled', 'default_action', 'log_level']
        return all(field in config_data for field in required_fields)

class PolicyManager:
    """Manages security policies"""
    
    def __init__(self, policy_file: str = "policies.json"):
        base_dir = os.path.dirname(__file__)
        self.policy_file = os.path.join(base_dir, policy_file)
        self.policies: List[Policy] = []
        self.policy_lock = threading.Lock()
        
        # Load policies
        self.load_policies()
    
    def load_policies(self) -> bool:
        """Load policies from file"""
        try:
            if os.path.exists(self.policy_file):
                with open(self.policy_file, 'r') as f:
                    policies_data = json.load(f)
                
                self.policies = []
                for policy_data in policies_data:
                    policy = Policy(
                        id=policy_data['id'],
                        name=policy_data['name'],
                        policy_type=PolicyType(policy_data['policy_type']),
                        description=policy_data['description'],
                        rules=policy_data['rules'],
                        conditions=policy_data['conditions'],
                        actions=[PolicyAction(action) for action in policy_data['actions']],
                        priority=policy_data['priority'],
                        enabled=policy_data['enabled'],
                        created_at=datetime.fromisoformat(policy_data['created_at']),
                        updated_at=datetime.fromisoformat(policy_data['updated_at']),
                        expires_at=datetime.fromisoformat(policy_data['expires_at']) if policy_data.get('expires_at') else None
                    )
                    self.policies.append(policy)
                
                return True
            else:
                # Create default policies
                self._create_default_policies()
                return True
        except Exception as e:
            print(f"Error loading policies: {e}")
            return False
    
    def save_policies(self) -> bool:
        """Save policies to file"""
        try:
            with self.policy_lock:
                policies_data = []
                for policy in self.policies:
                    policy_dict = asdict(policy)
                    policy_dict['policy_type'] = policy.policy_type.value
                    policy_dict['actions'] = [action.value for action in policy.actions]
                    policy_dict['created_at'] = policy.created_at.isoformat()
                    policy_dict['updated_at'] = policy.updated_at.isoformat()
                    if policy.expires_at:
                        policy_dict['expires_at'] = policy.expires_at.isoformat()
                    policies_data.append(policy_dict)
                
                with open(self.policy_file, 'w') as f:
                    json.dump(policies_data, f, indent=2)
                return True
        except Exception as e:
            print(f"Error saving policies: {e}")
            return False
    
    def _create_default_policies(self):
        """Create default security policies"""
        default_policies = [
            Policy(
                id="default_security",
                name="Default Security Policy",
                policy_type=PolicyType.SECURITY,
                description="Basic security policy for common threats",
                rules=[
                    {"type": "block", "pattern": "malicious_ip", "action": "DENY"},
                    {"type": "rate_limit", "threshold": 100, "action": "ALERT"}
                ],
                conditions=[
                    {"field": "source_ip", "operator": "in", "value": "blacklist"},
                    {"field": "packet_rate", "operator": ">", "value": 100}
                ],
                actions=[PolicyAction.DENY, PolicyAction.ALERT],
                priority=100,
                enabled=True,
                created_at=datetime.now(),
                updated_at=datetime.now()
            ),
            Policy(
                id="network_compliance",
                name="Network Compliance Policy",
                policy_type=PolicyType.COMPLIANCE,
                description="Ensure network traffic compliance",
                rules=[
                    {"type": "port_restriction", "allowed_ports": [80, 443, 22, 21]},
                    {"type": "protocol_restriction", "allowed_protocols": ["TCP", "UDP"]}
                ],
                conditions=[
                    {"field": "destination_port", "operator": "not_in", "value": [80, 443, 22, 21]},
                    {"field": "protocol", "operator": "not_in", "value": ["TCP", "UDP"]}
                ],
                actions=[PolicyAction.DENY, PolicyAction.LOG],
                priority=200,
                enabled=True,
                created_at=datetime.now(),
                updated_at=datetime.now()
            )
        ]
        
        for policy in default_policies:
            self.policies.append(policy)
        
        self.save_policies()
    
    def add_policy(self, policy: Policy) -> bool:
        """Add a new policy"""
        try:
            with self.policy_lock:
                self.policies.append(policy)
                return self.save_policies()
        except Exception as e:
            print(f"Error adding policy: {e}")
            return False
    
    def remove_policy(self, policy_id: str) -> bool:
        """Remove a policy by ID"""
        try:
            with self.policy_lock:
                self.policies = [p for p in self.policies if p.id != policy_id]
                return self.save_policies()
        except Exception as e:
            print(f"Error removing policy: {e}")
            return False
    
    def update_policy(self, policy_id: str, **kwargs) -> bool:
        """Update an existing policy"""
        try:
            with self.policy_lock:
                for policy in self.policies:
                    if policy.id == policy_id:
                        for key, value in kwargs.items():
                            if hasattr(policy, key):
                                setattr(policy, key, value)
                        policy.updated_at = datetime.now()
                        return self.save_policies()
                return False
        except Exception as e:
            print(f"Error updating policy: {e}")
            return False
    
    def get_policy(self, policy_id: str) -> Optional[Policy]:
        """Get policy by ID"""
        for policy in self.policies:
            if policy.id == policy_id:
                return policy
        return None
    
    def get_policies_by_type(self, policy_type: PolicyType) -> List[Policy]:
        """Get policies by type"""
        return [p for p in self.policies if p.policy_type == policy_type]
    
    def get_enabled_policies(self) -> List[Policy]:
        """Get enabled policies"""
        return [p for p in self.policies if p.enabled]
    
    def evaluate_policies(self, packet_info) -> List[PolicyAction]:
        """Evaluate packet against all policies"""
        actions = []
        
        for policy in self.get_enabled_policies():
            if self._policy_matches(policy, packet_info):
                actions.extend(policy.actions)
        
        return actions
    
    def _policy_matches(self, policy: Policy, packet_info) -> bool:
        """Check if policy matches packet"""
        try:
            for condition in policy.conditions:
                if not self._condition_matches(condition, packet_info):
                    return False
            return True
        except Exception as e:
            print(f"Error evaluating policy: {e}")
            return False
    
    def _condition_matches(self, condition: Dict[str, Any], packet_info) -> bool:
        """Check if condition matches packet"""
        field = condition.get('field')
        operator = condition.get('operator')
        value = condition.get('value')
        
        if not hasattr(packet_info, field):
            return False
        
        packet_value = getattr(packet_info, field)
        
        if operator == 'equals':
            return packet_value == value
        elif operator == 'not_equals':
            return packet_value != value
        elif operator == 'in':
            return packet_value in value
        elif operator == 'not_in':
            return packet_value not in value
        elif operator == '>':
            return packet_value > value
        elif operator == '<':
            return packet_value < value
        elif operator == '>=':
            return packet_value >= value
        elif operator == '<=':
            return packet_value <= value
        
        return False


class PolicyDialog(tk.Toplevel):
    """Dialog for adding/editing policies"""
    
    def __init__(self, parent, policy=None):
        super().__init__(parent)
        self.policy = policy
        self.result = None
        
        self.title("Edit Policy" if policy else "Add Policy")
        self.geometry("600x500")
        self.resizable(False, False)
        
        # Make dialog modal
        self.transient(parent)
        self.grab_set()
        
        self._create_widgets()
        
        # Center dialog
        self.update_idletasks()
        x = (self.winfo_screenwidth() // 2) - (self.winfo_width() // 2)
        y = (self.winfo_screenheight() // 2) - (self.winfo_height() // 2)
        self.geometry(f"+{x}+{y}")
    
    def _create_widgets(self):
        """Create dialog widgets"""
        # Main frame
        main_frame = ttk.Frame(self, padding="10")
        main_frame.pack(fill=tk.BOTH, expand=True)
        
        # Policy ID
        ttk.Label(main_frame, text="Policy ID:").grid(row=0, column=0, sticky=tk.W, pady=5)
        self.id_var = tk.StringVar(value=self.policy.id if self.policy else f"policy_{datetime.now().strftime('%Y%m%d%H%M%S')}")
        id_entry = ttk.Entry(main_frame, textvariable=self.id_var, width=40)
        id_entry.grid(row=0, column=1, pady=5, padx=5)
        if self.policy:  # Disable ID editing for existing policies
            id_entry.config(state='readonly')
        
        # Policy Name
        ttk.Label(main_frame, text="Name:").grid(row=1, column=0, sticky=tk.W, pady=5)
        self.name_var = tk.StringVar(value=self.policy.name if self.policy else "")
        ttk.Entry(main_frame, textvariable=self.name_var, width=40).grid(row=1, column=1, pady=5, padx=5)
        
        # Policy Type
        ttk.Label(main_frame, text="Type:").grid(row=2, column=0, sticky=tk.W, pady=5)
        self.type_var = tk.StringVar(value=self.policy.policy_type.value if self.policy else "SECURITY")
        ttk.Combobox(main_frame, textvariable=self.type_var, 
                    values=[pt.value for pt in PolicyType], width=37).grid(row=2, column=1, pady=5, padx=5)
        
        # Description
        ttk.Label(main_frame, text="Description:").grid(row=3, column=0, sticky=tk.NW, pady=5)
        self.description_text = tk.Text(main_frame, height=3, width=40)
        self.description_text.grid(row=3, column=1, pady=5, padx=5)
        if self.policy:
            self.description_text.insert(tk.END, self.policy.description)
        
        # Priority
        ttk.Label(main_frame, text="Priority:").grid(row=4, column=0, sticky=tk.W, pady=5)
        self.priority_var = tk.IntVar(value=self.policy.priority if self.policy else 100)
        ttk.Spinbox(main_frame, from_=1, to=1000, textvariable=self.priority_var, width=38).grid(row=4, column=1, pady=5, padx=5)
        
        # Actions
        ttk.Label(main_frame, text="Actions:").grid(row=5, column=0, sticky=tk.NW, pady=5)
        actions_frame = ttk.Frame(main_frame)
        actions_frame.grid(row=5, column=1, pady=5, padx=5, sticky=tk.W)
        
        self.action_vars = {}
        current_actions = [a.value for a in self.policy.actions] if self.policy else []
        for i, action in enumerate(PolicyAction):
            var = tk.BooleanVar(value=action.value in current_actions)
            self.action_vars[action.value] = var
            ttk.Checkbutton(actions_frame, text=action.value, variable=var).pack(anchor=tk.W)
        
        # Enabled
        self.enabled_var = tk.BooleanVar(value=self.policy.enabled if self.policy else True)
        ttk.Checkbutton(main_frame, text="Enabled", variable=self.enabled_var).grid(row=6, column=1, sticky=tk.W, pady=10, padx=5)
        
        # Buttons
        button_frame = ttk.Frame(main_frame)
        button_frame.grid(row=7, column=0, columnspan=2, pady=20)
        
        ttk.Button(button_frame, text="Save", command=self._on_save).pack(side=tk.LEFT, padx=5)
        ttk.Button(button_frame, text="Cancel", command=self._on_cancel).pack(side=tk.LEFT, padx=5)
    
    def _on_save(self):
        """Save policy"""
        # Validate input
        if not self.name_var.get().strip():
            messagebox.showerror("Validation Error", "Policy name is required")
            return
        
        # Get selected actions
        selected_actions = [PolicyAction(action) for action, var in self.action_vars.items() if var.get()]
        if not selected_actions:
            messagebox.showerror("Validation Error", "At least one action must be selected")
            return
        
        # Create policy
        self.result = Policy(
            id=self.id_var.get(),
            name=self.name_var.get(),
            policy_type=PolicyType(self.type_var.get()),
            description=self.description_text.get('1.0', tk.END).strip(),
            rules=self.policy.rules if self.policy else [],
            conditions=self.policy.conditions if self.policy else [],
            actions=selected_actions,
            priority=self.priority_var.get(),
            enabled=self.enabled_var.get(),
            created_at=self.policy.created_at if self.policy else datetime.now(),
            updated_at=datetime.now()
        )
        
        self.destroy()
    
    def _on_cancel(self):
        """Cancel dialog"""
        self.result = None
        self.destroy()


class ConfigurationGUI:
    """GUI for configuration management"""
    
    def __init__(self, parent, config_manager: ConfigurationManager, policy_manager: PolicyManager):
        self.parent = parent
        self.config_manager = config_manager
        self.policy_manager = policy_manager
        
        # Create notebook for tabs
        self.notebook = ttk.Notebook(parent)
        self.notebook.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        
        # Create tabs
        self._create_general_tab()
        self._create_security_tab()
        self._create_network_tab()
        self._create_policies_tab()

        # Save/Reload controls
        controls = ttk.Frame(parent)
        controls.pack(fill=tk.X, padx=10, pady=8)
        ttk.Button(controls, text="Save Configuration", command=self._on_save).pack(side=tk.LEFT, padx=5)
        ttk.Button(controls, text="Reload From File", command=self._on_reload).pack(side=tk.LEFT, padx=5)
        ttk.Button(controls, text="Reset to Defaults", command=self._on_reset).pack(side=tk.LEFT, padx=5)
    
    def _create_general_tab(self):
        """Create general configuration tab"""
        general_frame = ttk.Frame(self.notebook)
        self.notebook.add(general_frame, text="General")
        
        # General settings
        ttk.Label(general_frame, text="General Settings", font=('TkDefaultFont', 10, 'bold')).pack(anchor=tk.W, padx=10, pady=10)
        
        # Firewall enabled
        self.firewall_enabled_var = tk.BooleanVar(value=self.config_manager.get_config().firewall_enabled)
        ttk.Checkbutton(general_frame, text="Enable Firewall", variable=self.firewall_enabled_var).pack(anchor=tk.W, padx=20, pady=5)
        
        # Default action
        ttk.Label(general_frame, text="Default Action:").pack(anchor=tk.W, padx=20, pady=(10, 0))
        self.default_action_var = tk.StringVar(value=self.config_manager.get_config().default_action)
        ttk.Combobox(general_frame, textvariable=self.default_action_var, 
                    values=["ALLOW", "DENY"], state='readonly').pack(anchor=tk.W, padx=40, pady=5)
        
        # Log level
        ttk.Label(general_frame, text="Log Level:").pack(anchor=tk.W, padx=20, pady=(10, 0))
        self.log_level_var = tk.StringVar(value=self.config_manager.get_config().log_level)
        ttk.Combobox(general_frame, textvariable=self.log_level_var,
                    values=["DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"], 
                    state='readonly').pack(anchor=tk.W, padx=40, pady=5)
        
        # Connection settings
        ttk.Label(general_frame, text="Connection Settings", font=('TkDefaultFont', 10, 'bold')).pack(anchor=tk.W, padx=10, pady=(20, 10))
        
        ttk.Label(general_frame, text="Max Connections:").pack(anchor=tk.W, padx=20, pady=(5, 0))
        self.max_connections_var = tk.IntVar(value=self.config_manager.get_config().max_connections)
        ttk.Spinbox(general_frame, from_=100, to=10000, textvariable=self.max_connections_var, 
                   width=37).pack(anchor=tk.W, padx=40, pady=5)
        
        ttk.Label(general_frame, text="Connection Timeout (seconds):").pack(anchor=tk.W, padx=20, pady=(5, 0))
        self.connection_timeout_var = tk.IntVar(value=self.config_manager.get_config().connection_timeout)
        ttk.Spinbox(general_frame, from_=10, to=3600, textvariable=self.connection_timeout_var, 
                   width=37).pack(anchor=tk.W, padx=40, pady=5)
    
    def _create_security_tab(self):
        """Create security configuration tab"""
        security_frame = ttk.Frame(self.notebook)
        self.notebook.add(security_frame, text="Security")
        
        # Security settings
        ttk.Label(security_frame, text="Security Features", font=('TkDefaultFont', 10, 'bold')).pack(anchor=tk.W, padx=10, pady=10)
        
        # Stateful inspection
        self.stateful_var = tk.BooleanVar(value=self.config_manager.get_config().enable_stateful_inspection)
        ttk.Checkbutton(security_frame, text="Enable Stateful Inspection", 
                       variable=self.stateful_var).pack(anchor=tk.W, padx=20, pady=5)
        
        # Intrusion detection
        self.intrusion_var = tk.BooleanVar(value=self.config_manager.get_config().enable_intrusion_detection)
        ttk.Checkbutton(security_frame, text="Enable Intrusion Detection", 
                       variable=self.intrusion_var).pack(anchor=tk.W, padx=20, pady=5)
        
        # DoS protection
        self.dos_var = tk.BooleanVar(value=self.config_manager.get_config().enable_dos_protection)
        ttk.Checkbutton(security_frame, text="Enable DoS Protection", 
                       variable=self.dos_var).pack(anchor=tk.W, padx=20, pady=5)
        
        # Rate limiting
        ttk.Label(security_frame, text="Rate Limiting", font=('TkDefaultFont', 10, 'bold')).pack(anchor=tk.W, padx=10, pady=(20, 10))
        
        ttk.Label(security_frame, text="Max Packets Per Second:").pack(anchor=tk.W, padx=20, pady=(5, 0))
        self.max_packets_var = tk.IntVar(value=self.config_manager.get_config().max_packets_per_second)
        ttk.Spinbox(security_frame, from_=1000, to=100000, textvariable=self.max_packets_var, 
                   width=37).pack(anchor=tk.W, padx=40, pady=5)
        
        # Logging
        ttk.Label(security_frame, text="Logging Options", font=('TkDefaultFont', 10, 'bold')).pack(anchor=tk.W, padx=10, pady=(20, 10))
        
        self.log_packets_var = tk.BooleanVar(value=self.config_manager.get_config().log_packets)
        ttk.Checkbutton(security_frame, text="Log Packets", 
                       variable=self.log_packets_var).pack(anchor=tk.W, padx=20, pady=5)
        
        self.log_connections_var = tk.BooleanVar(value=self.config_manager.get_config().log_connections)
        ttk.Checkbutton(security_frame, text="Log Connections", 
                       variable=self.log_connections_var).pack(anchor=tk.W, padx=20, pady=5)
        
        self.log_security_events_var = tk.BooleanVar(value=self.config_manager.get_config().log_security_events)
        ttk.Checkbutton(security_frame, text="Log Security Events", 
                       variable=self.log_security_events_var).pack(anchor=tk.W, padx=20, pady=5)
    
    def _create_network_tab(self):
        """Create network configuration tab"""
        network_frame = ttk.Frame(self.notebook)
        self.notebook.add(network_frame, text="Network")
        
        # Create scrollable frame
        canvas = tk.Canvas(network_frame)
        scrollbar = ttk.Scrollbar(network_frame, orient="vertical", command=canvas.yview)
        scrollable_frame = ttk.Frame(canvas)
        
        scrollable_frame.bind(
            "<Configure>",
            lambda e: canvas.configure(scrollregion=canvas.bbox("all"))
        )
        
        canvas.create_window((0, 0), window=scrollable_frame, anchor="nw")
        canvas.configure(yscrollcommand=scrollbar.set)
        
        # Trusted networks
        ttk.Label(scrollable_frame, text="Trusted Networks", font=('TkDefaultFont', 10, 'bold')).pack(anchor=tk.W, padx=10, pady=10)
        ttk.Label(scrollable_frame, text="Enter one network per line (e.g., 192.168.1.0/24):").pack(anchor=tk.W, padx=20, pady=(0, 5))
        
        self.trusted_networks_text = tk.Text(scrollable_frame, height=5, width=60)
        self.trusted_networks_text.pack(anchor=tk.W, padx=40, pady=5)
        self.trusted_networks_text.insert(tk.END, '\n'.join(self.config_manager.get_config().trusted_networks))
        
        # Blocked networks
        ttk.Label(scrollable_frame, text="Blocked Networks", font=('TkDefaultFont', 10, 'bold')).pack(anchor=tk.W, padx=10, pady=(20, 10))
        ttk.Label(scrollable_frame, text="Enter one network per line (e.g., 10.0.0.0/8):").pack(anchor=tk.W, padx=20, pady=(0, 5))
        
        self.blocked_networks_text = tk.Text(scrollable_frame, height=5, width=60)
        self.blocked_networks_text.pack(anchor=tk.W, padx=40, pady=5)
        self.blocked_networks_text.insert(tk.END, '\n'.join(self.config_manager.get_config().blocked_networks))
        
        # Allowed ports
        ttk.Label(scrollable_frame, text="Allowed Ports", font=('TkDefaultFont', 10, 'bold')).pack(anchor=tk.W, padx=10, pady=(20, 10))
        ttk.Label(scrollable_frame, text="Enter comma-separated port numbers (e.g., 80, 443, 22):").pack(anchor=tk.W, padx=20, pady=(0, 5))
        
        self.allowed_ports_var = tk.StringVar(value=', '.join(map(str, self.config_manager.get_config().allowed_ports)))
        ttk.Entry(scrollable_frame, textvariable=self.allowed_ports_var, width=60).pack(anchor=tk.W, padx=40, pady=5)
        
        # Blocked ports
        ttk.Label(scrollable_frame, text="Blocked Ports", font=('TkDefaultFont', 10, 'bold')).pack(anchor=tk.W, padx=10, pady=(20, 10))
        ttk.Label(scrollable_frame, text="Enter comma-separated port numbers:").pack(anchor=tk.W, padx=20, pady=(0, 5))
        
        self.blocked_ports_var = tk.StringVar(value=', '.join(map(str, self.config_manager.get_config().blocked_ports)))
        ttk.Entry(scrollable_frame, textvariable=self.blocked_ports_var, width=60).pack(anchor=tk.W, padx=40, pady=5)
        
        # Pack canvas and scrollbar
        canvas.pack(side="left", fill="both", expand=True)
        scrollbar.pack(side="right", fill="y")