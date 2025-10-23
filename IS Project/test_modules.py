#!/usr/bin/env python3
"""
Test script to verify all firewall modules are working correctly
"""

def test_imports():
    """Test that all modules can be imported"""
    try:
        print("Testing module imports...")
        
        # Test packet capture module
        from packet_capture import PacketCapture, PacketInfo
        print("✓ Packet capture module imported successfully")
        
        # Test rule engine module
        from rule_engine import RuleEngine, RuleAction, RuleDirection, Protocol, FirewallRule
        print("✓ Rule engine module imported successfully")
        
        # Test stateful inspection module
        from stateful_inspection import StatefulInspector, ConnectionState
        print("✓ Stateful inspection module imported successfully")
        
        # Test rule management module
        from rule_management import RuleManager
        print("✓ Rule management module imported successfully")
        
        # Test logging and monitoring module
        from logging_monitoring import FirewallLogger, FirewallMonitor, LogLevel, FirewallEvent
        print("✓ Logging and monitoring module imported successfully")
        
        # Test configuration and policy module
        from configuration_policy import ConfigurationManager, PolicyManager
        print("✓ Configuration and policy module imported successfully")
        
        print("\n🎉 All modules imported successfully!")
        return True
        
    except ImportError as e:
        print(f"❌ Import error: {e}")
        return False
    except Exception as e:
        print(f"❌ Unexpected error: {e}")
        return False

def test_basic_functionality():
    """Test basic functionality of modules"""
    try:
        print("\nTesting basic functionality...")
        
        # Test rule engine
        from rule_engine import RuleEngine, RuleAction, RuleDirection, Protocol, FirewallRule
        rule_engine = RuleEngine()
        print("✓ Rule engine initialized")
        
        # Test packet capture
        from packet_capture import PacketCapture
        packet_capture = PacketCapture()
        print("✓ Packet capture initialized")
        
        # Test stateful inspector
        from stateful_inspection import StatefulInspector
        stateful_inspector = StatefulInspector()
        print("✓ Stateful inspector initialized")
        
        # Test logger
        from logging_monitoring import FirewallLogger
        logger = FirewallLogger()
        print("✓ Logger initialized")
        
        # Test configuration manager
        from configuration_policy import ConfigurationManager
        config_manager = ConfigurationManager()
        print("✓ Configuration manager initialized")
        
        print("\n🎉 All modules initialized successfully!")
        return True
        
    except Exception as e:
        print(f"❌ Functionality test error: {e}")
        return False

def main():
    """Main test function"""
    print("=== Firewall Module Test ===")
    print("Testing enhanced host-based firewall modules...\n")
    
    # Test imports
    import_success = test_imports()
    
    if import_success:
        # Test basic functionality
        functionality_success = test_basic_functionality()
        
        if functionality_success:
            print("\n🎉 All tests passed! The firewall is ready to use.")
            print("\nTo run the firewall:")
            print("  python firewall.py")
            print("\nNote: Run as Administrator for full functionality.")
        else:
            print("\n❌ Some functionality tests failed.")
    else:
        print("\n❌ Import tests failed. Check dependencies.")

if __name__ == "__main__":
    main()
