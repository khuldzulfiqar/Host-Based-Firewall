"""
Packet Capture Module
Enhanced packet capture with detailed parsing and metadata extraction
"""

import struct
import time
from datetime import datetime
from typing import Dict, Any, Optional
from dataclasses import dataclass
from pydivert import WinDivert, Packet

@dataclass
class PacketInfo:
    """Structured packet information"""
    timestamp: datetime
    direction: str  # 'IN' or 'OUT'
    src_ip: str
    dst_ip: str
    src_port: int
    dst_port: int
    protocol: str
    packet_size: int
    tcp_flags: Optional[str] = None
    payload_preview: Optional[bytes] = None
    raw_packet: Optional[bytes] = None

class PacketCapture:
    """Enhanced packet capture with detailed parsing"""
    
    def __init__(self, log_callback=None):
        self.log_callback = log_callback
        self.running = False
        self.captured_packets = []
        self.stats = {
            'total_packets': 0,
            'inbound_packets': 0,
            'outbound_packets': 0,
            'tcp_packets': 0,
            'udp_packets': 0,
            'icmp_packets': 0
        }
    
    def start_capture(self, filter_expression="true", packet_processor=None):
        """Start packet capture with optional filter"""
        self.running = True
        self.log_callback("Packet capture started...")
        self.packet_processor = packet_processor
        
        try:
            with WinDivert(filter_expression) as w:
                for packet in w:
                    if not self.running:
                        break
                    
                    packet_info = self._parse_packet(packet)
                    self._update_stats(packet_info)
                    self.captured_packets.append(packet_info)
                    
                    # Process packet through firewall if processor is available
                    if self.packet_processor:
                        try:
                            should_allow = self.packet_processor(packet_info)
                            # Send packet if allowed, drop if blocked
                            if should_allow:
                                w.send(packet)
                            else:
                                self.log_callback(f"❌ Blocked: {packet_info.src_ip} → {packet_info.dst_ip}")
                        except Exception as e:
                            self.log_callback(f"Processing error: {e}")
                            w.send(packet)  # Allow by default on error
                    else:
                        w.send(packet)  # Allow all if no processor
                    
                    if self.log_callback:
                        self._log_packet(packet_info)
                        
        except Exception as e:
            if self.log_callback:
                self.log_callback(f"Capture error: {e}")
    
    def stop_capture(self):
        """Stop packet capture"""
        self.running = False
        if self.log_callback:
            self.log_callback("Packet capture stopped.")
    
    def _parse_packet(self, packet: Packet) -> PacketInfo:
        """Parse packet and extract detailed information"""
        timestamp = datetime.now()
        direction = "IN" if packet.is_inbound else "OUT"
        
        # Extract IP addresses
        src_ip = packet.src_addr
        dst_ip = packet.dst_addr
        
        # Extract ports (if TCP/UDP)
        src_port = 0
        dst_port = 0
        if packet.protocol in [6, 17] and packet.payload and len(packet.payload) > 20:  # TCP or UDP
            try:
                # Parse TCP/UDP header
                tcp_udp_data = packet.payload[20:]  # Skip IP header
                if len(tcp_udp_data) >= 4:
                    src_port, dst_port = struct.unpack('!HH', tcp_udp_data[:4])
            except:
                pass
        
        # Determine protocol name
        protocol_map = {1: 'ICMP', 6: 'TCP', 17: 'UDP', 47: 'GRE', 50: 'ESP', 51: 'AH'}
        protocol_name = protocol_map.get(packet.protocol, f'Protocol-{packet.protocol}')
        
        # Extract TCP flags if TCP
        tcp_flags = None
        if packet.protocol == 6 and packet.payload and len(packet.payload) >= 40:
            try:
                tcp_header = packet.payload[20:40]
                flags_byte = tcp_header[13]
                flags = []
                if flags_byte & 0x01: flags.append('FIN')
                if flags_byte & 0x02: flags.append('SYN')
                if flags_byte & 0x04: flags.append('RST')
                if flags_byte & 0x08: flags.append('PSH')
                if flags_byte & 0x10: flags.append('ACK')
                if flags_byte & 0x20: flags.append('URG')
                tcp_flags = ','.join(flags) if flags else 'None'
            except:
                pass
        
        # Get payload preview (first 16 bytes)
        payload_preview = packet.payload[20:36] if packet.payload and len(packet.payload) > 20 else None
        
        return PacketInfo(
            timestamp=timestamp,
            direction=direction,
            src_ip=src_ip,
            dst_ip=dst_ip,
            src_port=src_port,
            dst_port=dst_port,
            protocol=protocol_name,
            packet_size=len(packet.raw),
            tcp_flags=tcp_flags,
            payload_preview=payload_preview,
            raw_packet=packet.raw
        )
    
    def _update_stats(self, packet_info: PacketInfo):
        """Update capture statistics"""
        self.stats['total_packets'] += 1
        
        if packet_info.direction == 'IN':
            self.stats['inbound_packets'] += 1
        else:
            self.stats['outbound_packets'] += 1
        
        if packet_info.protocol == 'TCP':
            self.stats['tcp_packets'] += 1
        elif packet_info.protocol == 'UDP':
            self.stats['udp_packets'] += 1
        elif packet_info.protocol == 'ICMP':
            self.stats['icmp_packets'] += 1
    
    def _log_packet(self, packet_info: PacketInfo):
        """Log packet information"""
        port_info = f":{packet_info.src_port} → :{packet_info.dst_port}" if packet_info.src_port > 0 else ""
        tcp_info = f" [{packet_info.tcp_flags}]" if packet_info.tcp_flags else ""
        
        log_msg = (f"[{packet_info.timestamp.strftime('%H:%M:%S')}] "
                  f"{packet_info.direction} {packet_info.src_ip}{port_info} → "
                  f"{packet_info.dst_ip} | {packet_info.protocol} "
                  f"({packet_info.packet_size} bytes){tcp_info}")
        
        self.log_callback(log_msg)
    
    def get_stats(self) -> Dict[str, Any]:
        """Get capture statistics"""
        return self.stats.copy()
    
    def get_recent_packets(self, count: int = 100) -> list:
        """Get recent captured packets"""
        return self.captured_packets[-count:] if self.captured_packets else []
    
    def clear_captured_packets(self):
        """Clear captured packets buffer"""
        self.captured_packets.clear()
        self.stats = {key: 0 for key in self.stats}