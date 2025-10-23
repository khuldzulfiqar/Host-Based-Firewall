"""
Rule Engine Module
Advanced filtering rules with multiple criteria support
"""

import re
import ipaddress
from typing import List, Dict, Any, Optional, Union
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
    id: str
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
        self.default_action = RuleAction.ALLOW
        
        # Load default rules
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
                description="Block access to private networks"
            ),
            FirewallRule(
                id="default_allow_dns",
                name="Allow DNS Queries",
                action=RuleAction.ALLOW,
                direction=RuleDirection.OUTBOUND,
                protocol=Protocol.UDP,
                dst_port=53,
                description="Allow DNS queries"
            ),
            FirewallRule(
                id="default_allow_http",
                name="Allow HTTP/HTTPS",
                action=RuleAction.ALLOW,
                direction=RuleDirection.OUTBOUND,
                protocol=Protocol.TCP,
                dst_port=80,
                description="Allow HTTP traffic"
            ),
            FirewallRule(
                id="default_allow_https",
                name="Allow HTTPS",
                action=RuleAction.ALLOW,
                direction=RuleDirection.OUTBOUND,
                protocol=Protocol.TCP,
                dst_port=443,
                description="Allow HTTPS traffic"
            )
        ]
        
        for rule in default_rules:
            self.add_rule(rule)
    
    def add_rule(self, rule: FirewallRule) -> bool:
        """Add a new firewall rule"""
        try:
            if not rule.id:
                rule.id = f"rule_{self.rule_counter}"
                self.rule_counter += 1
            
            # Validate rule
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
        """Remove a firewall rule by ID"""
        for i, rule in enumerate(self.rules):
            if rule.id == rule_id:
                removed_rule = self.rules.pop(i)
                if self.log_callback:
                    self.log_callback(f"Removed rule: {removed_rule.name}")
                return True
        return False
    
    def update_rule(self, rule_id: str, **kwargs) -> bool:
        """Update an existing rule"""
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
        """Get a rule by ID"""
        for rule in self.rules:
            if rule.id == rule_id:
                return rule
        return None
    
    def get_all_rules(self) -> List[FirewallRule]:
        """Get all rules"""
        return self.rules.copy()
    
    def get_enabled_rules(self) -> List[FirewallRule]:
        """Get only enabled rules"""
        return [rule for rule in self.rules if rule.enabled]
    
    def _validate_rule(self, rule: FirewallRule) -> bool:
        """Validate rule parameters"""
        try:
            # Validate IP addresses
            if rule.src_ip and not self._is_valid_ip_or_cidr(rule.src_ip):
                return False
            if rule.dst_ip and not self._is_valid_ip_or_cidr(rule.dst_ip):
                return False
            
            # Validate ports
            if rule.src_port and not (1 <= rule.src_port <= 65535):
                return False
            if rule.dst_port and not (1 <= rule.dst_port <= 65535):
                return False
            
            return True
        except:
            return False
    
    def _is_valid_ip_or_cidr(self, ip_str: str) -> bool:
        """Check if string is valid IP address or CIDR notation"""
        try:
            ipaddress.ip_network(ip_str, strict=False)
            return True
        except ValueError:
            return False
    
    def evaluate_packet(self, packet_info) -> tuple[bool, Optional[FirewallRule]]:
        """
        Evaluate packet against all rules
        Returns: (should_allow, matching_rule)
        """
        if not hasattr(packet_info, 'src_ip'):
            return True, None
        
        # Get enabled rules sorted by priority
        enabled_rules = sorted([r for r in self.rules if r.enabled], key=lambda x: x.priority)
        
        for rule in enabled_rules:
            if self._rule_matches_packet(rule, packet_info):
                action_allowed = rule.action == RuleAction.ALLOW
                if self.log_callback:
                    self.log_callback(f"Rule match: {rule.name} -> {rule.action.value}")
                return action_allowed, rule
        
        # No rule matched, use default action
        return self.default_action == RuleAction.ALLOW, None
    
    def _rule_matches_packet(self, rule: FirewallRule, packet_info) -> bool:
        """Check if a rule matches a packet"""
        try:
            # Check direction
            if rule.direction != RuleDirection.BOTH:
                packet_direction = RuleDirection.INBOUND if packet_info.direction == "IN" else RuleDirection.OUTBOUND
                if rule.direction != packet_direction:
                    return False
            
            # Check protocol
            if rule.protocol != Protocol.ANY:
                if rule.protocol.value != packet_info.protocol:
                    return False
            
            # Check source IP
            if rule.src_ip and not self._ip_matches(rule.src_ip, packet_info.src_ip):
                return False
            
            # Check destination IP
            if rule.dst_ip and not self._ip_matches(rule.dst_ip, packet_info.dst_ip):
                return False
            
            # Check source port
            if rule.src_port and hasattr(packet_info, 'src_port'):
                if packet_info.src_port != rule.src_port:
                    return False
            
            # Check destination port
            if rule.dst_port and hasattr(packet_info, 'dst_port'):
                if packet_info.dst_port != rule.dst_port:
                    return False
            
            return True
            
        except Exception as e:
            if self.log_callback:
                self.log_callback(f"Error matching rule: {e}")
            return False
    
    def _ip_matches(self, rule_ip: str, packet_ip: str) -> bool:
        """Check if packet IP matches rule IP (supports CIDR)"""
        try:
            if '/' in rule_ip:
                # CIDR notation
                network = ipaddress.ip_network(rule_ip, strict=False)
                packet_addr = ipaddress.ip_address(packet_ip)
                return packet_addr in network
            else:
                # Single IP
                return rule_ip == packet_ip
        except:
            return False
    
    def set_default_action(self, action: RuleAction):
        """Set default action for unmatched packets"""
        self.default_action = action
        if self.log_callback:
            self.log_callback(f"Default action set to: {action.value}")
    
    def get_rule_statistics(self) -> Dict[str, Any]:
        """Get rule engine statistics"""
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