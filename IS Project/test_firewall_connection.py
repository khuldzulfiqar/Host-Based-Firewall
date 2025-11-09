#!/usr/bin/env python3
"""
Test script to verify firewall packet processing is working
"""

import time
from firewall import EnhancedFirewall

def test_log_callback(message):
    print(f"[TEST] {message}")

def main():
    print("=== Testing Firewall Packet Processing ===")
    
    # Create firewall instance
    firewall = EnhancedFirewall(test_log_callback)
    
    print("✓ Firewall created successfully")
    
    # Test packet processing with a mock packet
    from packet_capture import PacketInfo
    from datetime import datetime
    
    # Create a mock packet for testing
    mock_packet = PacketInfo(
        timestamp=datetime.now(),
        direction="OUT",
        src_ip="192.168.1.100",
        dst_ip="8.8.8.8",
        src_port=12345,
        dst_port=53,
        protocol="UDP",
        packet_size=64,
        tcp_flags=None,
        payload_preview=None,
        raw_packet=None
    )
    
    print("✓ Mock packet created")
    
    # Test packet processing
    try:
        result = firewall.process_packet(mock_packet)
        print(f"✓ Packet processing result: {result}")
        
        # Get statistics
        stats = firewall.get_statistics()
        print(f"✓ Firewall stats: {stats['firewall_stats']}")
        
        if stats['firewall_stats']['packets_processed'] > 0:
            print("🎉 Packet processing is working!")
        else:
            print("❌ Packet processing not working - packets_processed is 0")
            
    except Exception as e:
        print(f"❌ Error processing packet: {e}")
    
    print("\n=== Test Complete ===")

if __name__ == "__main__":
    main()
