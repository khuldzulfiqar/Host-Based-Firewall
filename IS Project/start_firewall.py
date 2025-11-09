#!/usr/bin/env python3
"""
Startup script for the Enhanced Host-Based Firewall
Handles initialization and error checking
"""

import sys
import os
import traceback

<<<<<<< HEAD
# 🔐 Import authentication system
from auth_system import authenticate_user, ensure_default_users, change_password

def login():
    """Login with role-based access and password change enforcement"""
    ensure_default_users()
    print("=== Firewall Login ===")
    
    while True:
        username = input("Username: ")
        password = input("Password: ")

        success, message, user, role = authenticate_user(username, password)
        print(message)

        if success:
            # Force password change if needed
            if user.get("must_change_password", False):
                print("⚠️ You must change your password on first login.")
                new_pw = input("Enter new password: ")
                confirm_pw = input("Confirm new password: ")
                if new_pw != confirm_pw:
                    print("❌ Passwords do not match. Try login again.")
                    continue
                change_password(username, new_pw)
                print("✅ Password changed successfully. Please login again.")
                continue  # ask for login again with new password

            return user["role"]  # return role for RBAC
        else:
            # account locked
            if user and user.get("locked", False):
                input("Press Enter to exit...")
                sys.exit(1)
            # retry login
            print("Try again.\n")

=======
>>>>>>> 752be40f2a8e6162abbd420c5915312dbe69f252
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
        from rule_engine import RuleEngine, RuleAction  # <-- import here

        # 1️⃣ Initialize the rule engine with logger
        def logger(msg):
            print(msg)
        
        engine = RuleEngine(log_callback=logger)

        # 2️⃣ Set default action to DENY for security
        engine.set_default_action(RuleAction.DENY)
        
        # Create main window
        root = tk.Tk()
        gui = EnhancedFirewallGUI(root, role)

        
        gui.user_role = role

        # ⚙️ Step 4: Apply role-based access control
        if role != "admin":
            print("⚠️ Limited access: You can only view logs and statistics.")
            print("⚠️ Add, Edit, and Delete buttons are disabled for non-admin users.")
            
            # Disable configuration and policy modification tabs if they exist
            try:
                # Find and disable the Configuration tab
                for i in range(gui.notebook.index("end")):
                    tab_text = gui.notebook.tab(i, "text")
                    if tab_text.lower() == "configuration":
                        gui.notebook.tab(i, state="disabled")
                        print("⚠️ Configuration tab disabled for non-admin users.")
            except:
                pass

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
    
