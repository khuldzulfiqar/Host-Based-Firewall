import tkinter as tk
from tkinter import messagebox, ttk
import hashlib
import os

# Simple credentials store (in production, use a proper database)
VALID_CREDENTIALS = {
    'admin': hashlib.sha256('admin123'.encode()).hexdigest(),
    'guest': hashlib.sha256('guest123'.encode()).hexdigest(),
}

VALID_ROLES = {
    'admin': 'admin',
    'guest': 'guest'
}

def hash_password(password):
    """Hash a password using SHA256"""
    return hashlib.sha256(password.encode()).hexdigest()

def authenticate_user(username, password):
    """
    Authenticate a user with username and password.
    Returns a tuple: (success, message, user_dict, role)
    """
    if username not in VALID_CREDENTIALS:
        return False, "❌ Unknown username.", {"locked": False}, None
    
    password_hash = hash_password(password)
    
    if VALID_CREDENTIALS[username] != password_hash:
        return False, "❌ Incorrect password.", {"locked": False}, None
    
    user_dict = {"role": VALID_ROLES.get(username, 'guest'), "locked": False}
    return True, f"✅ Authentication successful. Welcome {username}!", user_dict, VALID_ROLES.get(username, 'guest')

def ensure_default_users():
    """
    Ensure default users (admin and guest) exist in the credentials store.
    This is called on startup to guarantee these users are available.
    """
    default_users = {
        'admin': hashlib.sha256('admin123'.encode()).hexdigest(),
        'guest': hashlib.sha256('guest123'.encode()).hexdigest(),
    }
    
    # Update VALID_CREDENTIALS with default users if they don't exist
    for username, password_hash in default_users.items():
        if username not in VALID_CREDENTIALS:
            VALID_CREDENTIALS[username] = password_hash
            VALID_ROLES[username] = username

def change_password(username, old_password, new_password):
    """
    Change the password for an existing user.
    Returns True if successful, False otherwise.
    """
    if username not in VALID_CREDENTIALS:
        return False
    
    # Verify old password
    old_password_hash = hash_password(old_password)
    if VALID_CREDENTIALS[username] != old_password_hash:
        return False
    
    # Update password
    new_password_hash = hash_password(new_password)
    VALID_CREDENTIALS[username] = new_password_hash
    return True

def login():
    """
    Display login GUI and return user role ('admin' or 'guest')
    """
    login_window = tk.Tk()
    login_window.title("Firewall Login")
    login_window.geometry("400x300")
    login_window.resizable(False, False)
    
    # Center window on screen
    login_window.update_idletasks()
    x = (login_window.winfo_screenwidth() // 2) - (login_window.winfo_width() // 2)
    y = (login_window.winfo_screenheight() // 2) - (login_window.winfo_height() // 2)
    login_window.geometry(f"+{x}+{y}")
    
    result = {'role': None}
    
    # Title
    title_frame = ttk.Frame(login_window)
    title_frame.pack(fill=tk.X, padx=20, pady=20)
    
    title_label = ttk.Label(title_frame, text="Enhanced Host-Based Firewall", 
                            font=("Arial", 16, "bold"))
    title_label.pack()
    
    subtitle_label = ttk.Label(title_frame, text="Login to continue", 
                               font=("Arial", 10))
    subtitle_label.pack()
    
    # Login form frame
    form_frame = ttk.Frame(login_window)
    form_frame.pack(fill=tk.BOTH, expand=True, padx=20, pady=10)
    
    # Username
    ttk.Label(form_frame, text="Username:", font=("Arial", 10)).grid(row=0, column=0, sticky=tk.W, pady=10)
    username_var = tk.StringVar()
    username_entry = ttk.Entry(form_frame, textvariable=username_var, width=25, font=("Arial", 10))
    username_entry.grid(row=0, column=1, sticky=tk.W, padx=10)
    username_entry.focus()
    
    # Password
    ttk.Label(form_frame, text="Password:", font=("Arial", 10)).grid(row=1, column=0, sticky=tk.W, pady=10)
    password_var = tk.StringVar()
    password_entry = ttk.Entry(form_frame, textvariable=password_var, width=25, font=("Arial", 10), show="*")
    password_entry.grid(row=1, column=1, sticky=tk.W, padx=10)
    
    # Quick login buttons for demo
    demo_frame = ttk.LabelFrame(login_window, text="Quick Login (Demo)", padding=10)
    demo_frame.pack(fill=tk.X, padx=20, pady=10)
    
    def quick_login_admin():
        username_var.set("admin")
        password_var.set("admin123")
        perform_login()
    
    def quick_login_guest():
        username_var.set("guest")
        password_var.set("guest123")
        perform_login()
    
    demo_btn_frame = ttk.Frame(demo_frame)
    demo_btn_frame.pack(fill=tk.X)
    
    ttk.Button(demo_btn_frame, text="Login as Admin", command=quick_login_admin).pack(side=tk.LEFT, padx=5)
    ttk.Button(demo_btn_frame, text="Login as Guest", command=quick_login_guest).pack(side=tk.LEFT, padx=5)
    
    ttk.Label(demo_frame, text="(admin: admin123, guest: guest123)", font=("Arial", 8, "italic")).pack(anchor=tk.W, pady=5)
    
    # Button frame
    button_frame = ttk.Frame(login_window)
    button_frame.pack(fill=tk.X, padx=20, pady=20)
    
    def perform_login():
        username = username_var.get().strip()
        password = password_var.get()
        
        if not username or not password:
            messagebox.showerror("Error", "Please enter username and password")
            return
        
        success, message, user_dict, role = authenticate_user(username, password)
        
        if not success:
            messagebox.showerror("Login Failed", message)
            password_var.set("")
            password_entry.focus()
            return
        
        # Login successful
        result['role'] = role
        login_window.destroy()
    
    ttk.Button(button_frame, text="Login", command=perform_login).pack(side=tk.LEFT, padx=5)
    ttk.Button(button_frame, text="Exit", command=login_window.quit).pack(side=tk.LEFT, padx=5)
    
    # Bind Enter key to login
    login_window.bind('<Return>', lambda e: perform_login())
    
    # Keep window on top
    login_window.attributes('-topmost', True)
    
    # Wait for login
    login_window.mainloop()
    
    # Check if user closed without logging in
    if result['role'] is None:
        return 'guest'  # Default to guest if closed
    
    return result['role']

if __name__ == "__main__":
    # Test the login
    ensure_default_users()
    role = login()
    print(f"Logged in as: {role}")
