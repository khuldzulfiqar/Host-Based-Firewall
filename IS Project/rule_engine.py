"""
Rule Engine Module
Advanced filtering rules with multiple criteria support
"""

import ipaddress
from typing import List, Dict, Any, Optional
from dataclasses import dataclass
from enum import Enum
from datetime import datetime

class RuleAction(Enum):
    ALLOW = "ALLOW"
    DENY = "DENY"
    LOG = "LOG"

class RuleDirection(Enum):
    INBOUND = "INBOUND"
    OUTBOUND = "OUTBOUND"
    BOTH = "BOTH"

class Protocol(Enum):
    TCP = "TCP"
    UDP = "UDP"
    ICMP = "ICMP"
    ANY = "ANY"

@dataclass
class FirewallRule:
    """Firewall rule definition"""
    name: str
    action: RuleAction
    direction: RuleDirection
    protocol: Protocol
    src_ip: Optional[str] = None
    dst_ip: Optional[str] = None
    src_port: Optional[int] = None
    dst_port: Optional[int] = None
    enabled: bool = True
    priority: int = 100
    id: Optional[str] = None
    created_at: datetime = None
    description: str = ""
    
    def __post_init__(self):
        if self.created_at is None:
            self.created_at = datetime.now()

class RuleEngine:
    """Advanced rule engine for packet filtering"""
    
    def __init__(self, log_callback=None):
        self.log_callback = log_callback
        self.rules: List[FirewallRule] = []
        self.rule_counter = 0
        self.default_action = RuleAction.DENY  # Safer default
        
        self._load_default_rules()
    
    def _load_default_rules(self):
        """Load default firewall rules"""
        default_rules = [
            FirewallRule(
                id="default_deny_private",
                name="Deny Private Network Access",
                action=RuleAction.DENY,
                direction=RuleDirection.OUTBOUND,
                protocol=Protocol.ANY,
                dst_ip="10.0.0.0/8",
                description="Block access to private networks",
                priority=10
            ),
            FirewallRule(
                id="block_rdp",
                name="Block RDP Inbound",
                action=RuleAction.DENY,
                direction=RuleDirection.INBOUND,
                protocol=Protocol.TCP,
                dst_port=3389,
                description="Block remote desktop attacks",
                priority=15
            ),
            FirewallRule(
                id="allow_lan",
                name="Allow LAN traffic",
                action=RuleAction.ALLOW,
                direction=RuleDirection.BOTH,
                protocol=Protocol.ANY,
                src_ip="192.168.0.0/16",
                dst_ip="192.168.0.0/16",
                description="Allow all traffic inside local network",
                priority=20
            ),
            FirewallRule(
                id="default_allow_dns",
                name="Allow DNS Queries",
                action=RuleAction.ALLOW,
                direction=RuleDirection.OUTBOUND,
                protocol=Protocol.UDP,
                dst_port=53,
                description="Allow DNS queries",
                priority=30
            ),
            FirewallRule(
                id="default_allow_http",
                name="Allow HTTP",
                action=RuleAction.ALLOW,
                direction=RuleDirection.OUTBOUND,
                protocol=Protocol.TCP,
                dst_port=80,
                description="Allow HTTP traffic",
                priority=40
            ),
            FirewallRule(
                id="default_allow_https",
                name="Allow HTTPS",
                action=RuleAction.ALLOW,
                direction=RuleDirection.OUTBOUND,
                protocol=Protocol.TCP,
                dst_port=443,
                description="Allow HTTPS traffic",
                priority=45
            ),
            FirewallRule(
                id="default_allow_http_in",
                name="Allow HTTP Inbound",
                action=RuleAction.ALLOW,
                direction=RuleDirection.INBOUND,
                protocol=Protocol.TCP,
                src_port=80,
                description="Allow incoming HTTP responses",
                priority=50
            ),
            FirewallRule(
                id="default_allow_https_in",
                name="Allow HTTPS Inbound",
                action=RuleAction.ALLOW,
                direction=RuleDirection.INBOUND,
                protocol=Protocol.TCP,
                src_port=443,
                description="Allow incoming HTTPS responses",
                priority=55
            ),
            FirewallRule(
                id="allow_vpn_udp",
                name="Allow VPN UDP",
                action=RuleAction.ALLOW,
                direction=RuleDirection.BOTH,
                protocol=Protocol.UDP,
                dst_port=1194,
                description="Allow VPN UDP traffic",
                priority=60
            ),
            FirewallRule(
                id="allow_vpn_tcp",
                name="Allow VPN TCP",
                action=RuleAction.ALLOW,
                direction=RuleDirection.BOTH,
                protocol=Protocol.TCP,
                dst_port=443,
                description="Allow VPN TCP traffic",
                priority=61
            ),
            FirewallRule(
                id="allow_icmp",
                name="Allow ICMP",
                action=RuleAction.ALLOW,
                direction=RuleDirection.BOTH,
                protocol=Protocol.ICMP,
                description="Allow ping requests/replies",
                priority=70
            ),
            FirewallRule(
                id="log_unknown_tcp",
                name="Log Unknown TCP Traffic",
                action=RuleAction.LOG,
                direction=RuleDirection.OUTBOUND,
                protocol=Protocol.TCP,
                description="Log outbound TCP traffic not matching allow rules",
                priority=100
            )
        ]
        
        for rule in default_rules:
            self.add_rule(rule)
    
    # ---- Rule Management ----
    def add_rule(self, rule: FirewallRule) -> bool:
        try:
            if not rule.id:
                rule.id = f"rule_{self.rule_counter}"
                self.rule_counter += 1
            
            if self._validate_rule(rule):
                self.rules.append(rule)
                self.rules.sort(key=lambda x: x.priority)
                if self.log_callback:
                    self.log_callback(f"Added rule: {rule.name} ({rule.action.value})")
                return True
            return False
        except Exception as e:
            if self.log_callback:
                self.log_callback(f"Error adding rule: {e}")
            return False
    
    def remove_rule(self, rule_id: str) -> bool:
        for i, rule in enumerate(self.rules):
            if rule.id == rule_id:
                removed_rule = self.rules.pop(i)
                if self.log_callback:
                    self.log_callback(f"Removed rule: {removed_rule.name}")
                return True
        return False
    
    def update_rule(self, rule_id: str, **kwargs) -> bool:
        for rule in self.rules:
            if rule.id == rule_id:
                for key, value in kwargs.items():
                    if hasattr(rule, key):
                        setattr(rule, key, value)
                if self.log_callback:
                    self.log_callback(f"Updated rule: {rule.name}")
                return True
        return False
    
    def get_rule(self, rule_id: str) -> Optional[FirewallRule]:
        for rule in self.rules:
            if rule.id == rule_id:
                return rule
        return None
    
    def get_all_rules(self) -> List[FirewallRule]:
        return self.rules.copy()
    
    def get_enabled_rules(self) -> List[FirewallRule]:
        return [rule for rule in self.rules if rule.enabled]
    
    # ---- Packet Evaluation ----
    def evaluate_packet(self, packet_info) -> tuple[bool, Optional[FirewallRule]]:
        if not hasattr(packet_info, 'src_ip'):
            return True, None
        
        enabled_rules = sorted([r for r in self.rules if r.enabled], key=lambda x: x.priority)
        
        for rule in enabled_rules:
            if self._rule_matches_packet(rule, packet_info):
                if rule.action == RuleAction.LOG:
                    if self.log_callback:
                        self.log_callback(f"Rule match: {rule.name} -> LOGGED")
                    return self.default_action == RuleAction.ALLOW, rule
                
                action_allowed = rule.action == RuleAction.ALLOW
                if self.log_callback:
                    self.log_callback(f"Rule match: {rule.name} -> {rule.action.value}")
                return action_allowed, rule
        
        return self.default_action == RuleAction.ALLOW, None
    
    def _rule_matches_packet(self, rule: FirewallRule, packet_info) -> bool:
        try:
            if rule.direction != RuleDirection.BOTH:
                packet_direction = RuleDirection.INBOUND if packet_info.direction == "IN" else RuleDirection.OUTBOUND
                if rule.direction != packet_direction:
                    return False
            
            if rule.protocol != Protocol.ANY:
                if rule.protocol.value != packet_info.protocol:
                    return False
            
            if rule.src_ip and not self._ip_matches(rule.src_ip, packet_info.src_ip):
                return False
            if rule.dst_ip and not self._ip_matches(rule.dst_ip, packet_info.dst_ip):
                return False
            
            if rule.src_port and hasattr(packet_info, 'src_port'):
                if packet_info.src_port != rule.src_port:
                    return False
            if rule.dst_port and hasattr(packet_info, 'dst_port'):
                if packet_info.dst_port != rule.dst_port:
                    return False
            
            return True
        except Exception as e:
            if self.log_callback:
                self.log_callback(f"Error matching rule: {e}")
            return False
    
    def _ip_matches(self, rule_ip: str, packet_ip: str) -> bool:
        try:
            if '/' in rule_ip:
                network = ipaddress.ip_network(rule_ip, strict=False)
                return ipaddress.ip_address(packet_ip) in network
            return rule_ip == packet_ip
        except:
            return False
    
    # ---- Misc ----
    def set_default_action(self, action: RuleAction):
        self.default_action = action
        if self.log_callback:
            self.log_callback(f"Default action set to: {action.value}")
    
    def get_rule_statistics(self) -> Dict[str, Any]:
        enabled_count = len([r for r in self.rules if r.enabled])
        disabled_count = len([r for r in self.rules if not r.enabled])
        
        action_counts = {}
        for rule in self.rules:
            action = rule.action.value
            action_counts[action] = action_counts.get(action, 0) + 1
        
        return {
            'total_rules': len(self.rules),
            'enabled_rules': enabled_count,
            'disabled_rules': disabled_count,
            'action_counts': action_counts,
            'default_action': self.default_action.value
        }
    def _validate_rule(self, rule: FirewallRule) -> bool:

        try:
            if rule.src_ip and not self._is_valid_ip_or_cidr(rule.src_ip):
                return False
            if rule.dst_ip and not self._is_valid_ip_or_cidr(rule.dst_ip):
                return False
            if rule.src_port and not (1 <= rule.src_port <= 65535):
                return False
            if rule.dst_port and not (1 <= rule.dst_port <= 65535):
                return False
            return True
        except:
            return False
        
if __name__ == "__main__":
    # Create an instance of RuleEngine and print loaded rules
    engine = RuleEngine(log_callback=print)
    print("Loaded rules:", [r.name for r in engine.rules])

