#!/usr/bin/env python3
"""
Startup script for the Enhanced Host-Based Firewall
Handles initialization and error checking
"""

import sys
import os
import traceback

def check_requirements():
    """Check if all required modules are available"""
    try:
        import tkinter
        print("✓ Tkinter available")
    except ImportError:
        print("❌ Tkinter not available. Please install tkinter.")
        return False
    
    try:
        import pydivert
        print("✓ PyDivert available")
    except ImportError:
        print("❌ PyDivert not available. Please install: pip install pydivert==2.1.0")
        return False
    
    try:
        import psutil
        print("✓ Psutil available")
    except ImportError:
        print("❌ Psutil not available. Please install: pip install psutil")
        return False
    
    return True

def check_permissions():
    """Check if running with appropriate permissions"""
    try:
        import ctypes
        is_admin = ctypes.windll.shell32.IsUserAnAdmin()
        if is_admin:
            print("✓ Running with Administrator privileges")
        else:
            print("⚠️  Not running as Administrator - some features may be limited")
        return True
    except:
        print("⚠️  Could not check administrator status")
        return True

def main():
    """Main startup function"""
    print("=== Enhanced Host-Based Firewall Startup ===")
    print("Checking system requirements...\n")
    
    # Check requirements
    if not check_requirements():
        print("\n❌ Missing requirements. Please install missing dependencies.")
        input("Press Enter to exit...")
        return
    
    # Check permissions
    check_permissions()
    
    print("\nStarting Enhanced Host-Based Firewall...")
    
    try:
        # Import and run the main application
        from firewall import EnhancedFirewallGUI
        import tkinter as tk
        
        # Create main window
        root = tk.Tk()
        
        # Create and run GUI
        gui = EnhancedFirewallGUI(root)
        
        print("✓ Firewall GUI initialized successfully")
        print("✓ Application is ready to use")
        print("\nNote: Run as Administrator for full packet capture functionality")
        
        # Start the GUI main loop
        root.mainloop()
        
    except ImportError as e:
        print(f"❌ Import error: {e}")
        print("Please ensure all modules are in the same directory")
        input("Press Enter to exit...")
        
    except Exception as e:
        print(f"❌ Unexpected error: {e}")
        print("\nFull error details:")
        traceback.print_exc()
        input("Press Enter to exit...")

if __name__ == "__main__":
    main()
