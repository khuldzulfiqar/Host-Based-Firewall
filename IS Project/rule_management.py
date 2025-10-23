"""
Rule Management Module
GUI and CLI interfaces for managing firewall rules
"""

import tkinter as tk
from tkinter import ttk, messagebox, simpledialog
from typing import List, Optional, Dict, Any
import json
import os
from datetime import datetime
from rule_engine import FirewallRule, RuleAction, RuleDirection, Protocol, RuleEngine

class RuleManagementGUI:
    """GUI interface for rule management"""
    
    def __init__(self, parent, rule_engine: RuleEngine):
        self.parent = parent
        self.rule_engine = rule_engine
        self.selected_rule = None
        
        # Create main frame
        self.frame = ttk.Frame(parent)
        self.frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        
        # Create rule list
        self._create_rule_list()
        
        # Create rule details frame
        self._create_rule_details()
        
        # Create buttons
        self._create_buttons()
        
        # Load rules
        self._refresh_rule_list()
    
    def _create_rule_list(self):
        """Create rule list treeview"""
        # Rule list frame
        list_frame = ttk.LabelFrame(self.frame, text="Firewall Rules")
        list_frame.pack(fill=tk.BOTH, expand=True, padx=(0, 5), pady=(0, 10))
        
        # Treeview for rules
        columns = ('ID', 'Name', 'Action', 'Direction', 'Protocol', 'Source', 'Destination', 'Ports', 'Enabled')
        self.rule_tree = ttk.Treeview(list_frame, columns=columns, show='headings', height=10)
        
        # Configure columns
        for col in columns:
            self.rule_tree.heading(col, text=col)
            self.rule_tree.column(col, width=100)
        
        # Scrollbar
        scrollbar = ttk.Scrollbar(list_frame, orient=tk.VERTICAL, command=self.rule_tree.yview)
        self.rule_tree.configure(yscrollcommand=scrollbar.set)
        
        # Pack treeview and scrollbar
        self.rule_tree.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
        
        # Bind selection
        self.rule_tree.bind('<<TreeviewSelect>>', self._on_rule_select)
    
    def _create_rule_details(self):
        """Create rule details frame"""
        details_frame = ttk.LabelFrame(self.frame, text="Rule Details")
        details_frame.pack(fill=tk.X, padx=(5, 0), pady=(0, 10))
        
        # Create form fields
        self._create_form_fields(details_frame)
    
    def _create_form_fields(self, parent):
        """Create form fields for rule editing"""
        # Basic info
        basic_frame = ttk.Frame(parent)
        basic_frame.pack(fill=tk.X, padx=5, pady=5)
        
        # Name
        ttk.Label(basic_frame, text="Name:").grid(row=0, column=0, sticky=tk.W, padx=(0, 5))
        self.name_var = tk.StringVar()
        self.name_entry = ttk.Entry(basic_frame, textvariable=self.name_var, width=30)
        self.name_entry.grid(row=0, column=1, sticky=tk.W, padx=(0, 20))
        
        # Action
        ttk.Label(basic_frame, text="Action:").grid(row=0, column=2, sticky=tk.W, padx=(0, 5))
        self.action_var = tk.StringVar()
        self.action_combo = ttk.Combobox(basic_frame, textvariable=self.action_var, 
                                        values=[action.value for action in RuleAction], width=10)
        self.action_combo.grid(row=0, column=3, sticky=tk.W)
        
        # Direction
        ttk.Label(basic_frame, text="Direction:").grid(row=1, column=0, sticky=tk.W, padx=(0, 5), pady=(5, 0))
        self.direction_var = tk.StringVar()
        self.direction_combo = ttk.Combobox(basic_frame, textvariable=self.direction_var,
                                          values=[direction.value for direction in RuleDirection], width=10)
        self.direction_combo.grid(row=1, column=1, sticky=tk.W, padx=(0, 20), pady=(5, 0))
        
        # Protocol
        ttk.Label(basic_frame, text="Protocol:").grid(row=1, column=2, sticky=tk.W, padx=(0, 5), pady=(5, 0))
        self.protocol_var = tk.StringVar()
        self.protocol_combo = ttk.Combobox(basic_frame, textvariable=self.protocol_var,
                                          values=[protocol.value for protocol in Protocol], width=10)
        self.protocol_combo.grid(row=1, column=3, sticky=tk.W, pady=(5, 0))
        
        # Network info
        network_frame = ttk.Frame(parent)
        network_frame.pack(fill=tk.X, padx=5, pady=5)
        
        # Source IP
        ttk.Label(network_frame, text="Source IP:").grid(row=0, column=0, sticky=tk.W, padx=(0, 5))
        self.src_ip_var = tk.StringVar()
        self.src_ip_entry = ttk.Entry(network_frame, textvariable=self.src_ip_var, width=20)
        self.src_ip_entry.grid(row=0, column=1, sticky=tk.W, padx=(0, 20))
        
        # Destination IP
        ttk.Label(network_frame, text="Destination IP:").grid(row=0, column=2, sticky=tk.W, padx=(0, 5))
        self.dst_ip_var = tk.StringVar()
        self.dst_ip_entry = ttk.Entry(network_frame, textvariable=self.dst_ip_var, width=20)
        self.dst_ip_entry.grid(row=0, column=3, sticky=tk.W)
        
        # Ports
        ttk.Label(network_frame, text="Source Port:").grid(row=1, column=0, sticky=tk.W, padx=(0, 5), pady=(5, 0))
        self.src_port_var = tk.StringVar()
        self.src_port_entry = ttk.Entry(network_frame, textvariable=self.src_port_var, width=10)
        self.src_port_entry.grid(row=1, column=1, sticky=tk.W, padx=(0, 20), pady=(5, 0))
        
        ttk.Label(network_frame, text="Destination Port:").grid(row=1, column=2, sticky=tk.W, padx=(0, 5), pady=(5, 0))
        self.dst_port_var = tk.StringVar()
        self.dst_port_entry = ttk.Entry(network_frame, textvariable=self.dst_port_var, width=10)
        self.dst_port_entry.grid(row=1, column=3, sticky=tk.W, pady=(5, 0))
        
        # Additional options
        options_frame = ttk.Frame(parent)
        options_frame.pack(fill=tk.X, padx=5, pady=5)
        
        # Priority
        ttk.Label(options_frame, text="Priority:").grid(row=0, column=0, sticky=tk.W, padx=(0, 5))
        self.priority_var = tk.StringVar(value="100")
        self.priority_entry = ttk.Entry(options_frame, textvariable=self.priority_var, width=10)
        self.priority_entry.grid(row=0, column=1, sticky=tk.W, padx=(0, 20))
        
        # Enabled checkbox
        self.enabled_var = tk.BooleanVar(value=True)
        self.enabled_check = ttk.Checkbutton(options_frame, text="Enabled", variable=self.enabled_var)
        self.enabled_check.grid(row=0, column=2, sticky=tk.W)
        
        # Description
        ttk.Label(options_frame, text="Description:").grid(row=1, column=0, sticky=tk.W, padx=(0, 5), pady=(5, 0))
        self.description_var = tk.StringVar()
        self.description_entry = ttk.Entry(options_frame, textvariable=self.description_var, width=50)
        self.description_entry.grid(row=1, column=1, columnspan=3, sticky=tk.W, pady=(5, 0))
    
    def _create_buttons(self):
        """Create control buttons"""
        button_frame = ttk.Frame(self.frame)
        button_frame.pack(fill=tk.X, padx=5, pady=5)
        
        ttk.Button(button_frame, text="Add Rule", command=self._add_rule).pack(side=tk.LEFT, padx=(0, 5))
        ttk.Button(button_frame, text="Update Rule", command=self._update_rule).pack(side=tk.LEFT, padx=(0, 5))
        ttk.Button(button_frame, text="Delete Rule", command=self._delete_rule).pack(side=tk.LEFT, padx=(0, 5))
        ttk.Button(button_frame, text="Clear Form", command=self._clear_form).pack(side=tk.LEFT, padx=(0, 5))
        ttk.Button(button_frame, text="Import Rules", command=self._import_rules).pack(side=tk.LEFT, padx=(0, 5))
        ttk.Button(button_frame, text="Export Rules", command=self._export_rules).pack(side=tk.LEFT, padx=(0, 5))
        ttk.Button(button_frame, text="Refresh", command=self._refresh_rule_list).pack(side=tk.LEFT, padx=(0, 5))
    
    def _refresh_rule_list(self):
        """Refresh the rule list display"""
        # Clear existing items
        for item in self.rule_tree.get_children():
            self.rule_tree.delete(item)
        
        # Add rules
        for rule in self.rule_engine.get_all_rules():
            ports = f"{rule.src_port or 'Any'}:{rule.dst_port or 'Any'}"
            self.rule_tree.insert('', 'end', values=(
                rule.id,
                rule.name,
                rule.action.value,
                rule.direction.value,
                rule.protocol.value,
                rule.src_ip or 'Any',
                rule.dst_ip or 'Any',
                ports,
                'Yes' if rule.enabled else 'No'
            ))
    
    def _on_rule_select(self, event):
        """Handle rule selection"""
        selection = self.rule_tree.selection()
        if not selection:
            return
        
        item = self.rule_tree.item(selection[0])
        rule_id = item['values'][0]
        
        rule = self.rule_engine.get_rule(rule_id)
        if rule:
            self._populate_form(rule)
            self.selected_rule = rule
    
    def _populate_form(self, rule: FirewallRule):
        """Populate form with rule data"""
        self.name_var.set(rule.name)
        self.action_var.set(rule.action.value)
        self.direction_var.set(rule.direction.value)
        self.protocol_var.set(rule.protocol.value)
        self.src_ip_var.set(rule.src_ip or '')
        self.dst_ip_var.set(rule.dst_ip or '')
        self.src_port_var.set(str(rule.src_port) if rule.src_port else '')
        self.dst_port_var.set(str(rule.dst_port) if rule.dst_port else '')
        self.priority_var.set(str(rule.priority))
        self.enabled_var.set(rule.enabled)
        self.description_var.set(rule.description)
    
    def _clear_form(self):
        """Clear form fields"""
        self.name_var.set('')
        self.action_var.set('')
        self.direction_var.set('')
        self.protocol_var.set('')
        self.src_ip_var.set('')
        self.dst_ip_var.set('')
        self.src_port_var.set('')
        self.dst_port_var.set('')
        self.priority_var.set('100')
        self.enabled_var.set(True)
        self.description_var.set('')
        self.selected_rule = None
    
    def _add_rule(self):
        """Add new rule"""
        try:
            rule = self._create_rule_from_form()
            if self.rule_engine.add_rule(rule):
                self._refresh_rule_list()
                self._clear_form()
                messagebox.showinfo("Success", "Rule added successfully")
            else:
                messagebox.showerror("Error", "Failed to add rule")
        except Exception as e:
            messagebox.showerror("Error", f"Error adding rule: {e}")
    
    def _update_rule(self):
        """Update selected rule"""
        if not self.selected_rule:
            messagebox.showwarning("Warning", "Please select a rule to update")
            return
        
        try:
            rule_data = self._get_form_data()
            if self.rule_engine.update_rule(self.selected_rule.id, **rule_data):
                self._refresh_rule_list()
                messagebox.showinfo("Success", "Rule updated successfully")
            else:
                messagebox.showerror("Error", "Failed to update rule")
        except Exception as e:
            messagebox.showerror("Error", f"Error updating rule: {e}")
    
    def _delete_rule(self):
        """Delete selected rule"""
        if not self.selected_rule:
            messagebox.showwarning("Warning", "Please select a rule to delete")
            return
        
        if messagebox.askyesno("Confirm", f"Delete rule '{self.selected_rule.name}'?"):
            if self.rule_engine.remove_rule(self.selected_rule.id):
                self._refresh_rule_list()
                self._clear_form()
                messagebox.showinfo("Success", "Rule deleted successfully")
            else:
                messagebox.showerror("Error", "Failed to delete rule")
    
    def _create_rule_from_form(self) -> FirewallRule:
        """Create rule object from form data"""
        form_data = self._get_form_data()
        return FirewallRule(**form_data)
    
    def _get_form_data(self) -> Dict[str, Any]:
        """Get form data as dictionary"""
        data = {
            'name': self.name_var.get(),
            'action': RuleAction(self.action_var.get()),
            'direction': RuleDirection(self.direction_var.get()),
            'protocol': Protocol(self.protocol_var.get()),
            'enabled': self.enabled_var.get(),
            'priority': int(self.priority_var.get()) if self.priority_var.get() else 100,
            'description': self.description_var.get()
        }
        
        # Optional fields
        if self.src_ip_var.get():
            data['src_ip'] = self.src_ip_var.get()
        if self.dst_ip_var.get():
            data['dst_ip'] = self.dst_ip_var.get()
        if self.src_port_var.get():
            data['src_port'] = int(self.src_port_var.get())
        if self.dst_port_var.get():
            data['dst_port'] = int(self.dst_port_var.get())
        
        return data
    
    def _import_rules(self):
        """Import rules from file"""
        try:
            filename = tk.filedialog.askopenfilename(
                title="Import Rules",
                filetypes=[("JSON files", "*.json"), ("All files", "*.*")]
            )
            if filename:
                with open(filename, 'r') as f:
                    rules_data = json.load(f)
                
                imported_count = 0
                for rule_data in rules_data:
                    rule = FirewallRule(**rule_data)
                    if self.rule_engine.add_rule(rule):
                        imported_count += 1
                
                self._refresh_rule_list()
                messagebox.showinfo("Success", f"Imported {imported_count} rules")
        except Exception as e:
            messagebox.showerror("Error", f"Error importing rules: {e}")
    
    def _export_rules(self):
        """Export rules to file"""
        try:
            filename = tk.filedialog.asksaveasfilename(
                title="Export Rules",
                defaultextension=".json",
                filetypes=[("JSON files", "*.json"), ("All files", "*.*")]
            )
            if filename:
                rules_data = []
                for rule in self.rule_engine.get_all_rules():
                    rule_dict = {
                        'id': rule.id,
                        'name': rule.name,
                        'action': rule.action.value,
                        'direction': rule.direction.value,
                        'protocol': rule.protocol.value,
                        'src_ip': rule.src_ip,
                        'dst_ip': rule.dst_ip,
                        'src_port': rule.src_port,
                        'dst_port': rule.dst_port,
                        'enabled': rule.enabled,
                        'priority': rule.priority,
                        'description': rule.description,
                        'created_at': rule.created_at.isoformat() if rule.created_at else None
                    }
                    rules_data.append(rule_dict)
                
                with open(filename, 'w') as f:
                    json.dump(rules_data, f, indent=2)
                
                messagebox.showinfo("Success", f"Exported {len(rules_data)} rules to {filename}")
        except Exception as e:
            messagebox.showerror("Error", f"Error exporting rules: {e}")

class RuleManager:
    """Main rule management class"""
    
    def __init__(self, rule_engine: RuleEngine):
        self.rule_engine = rule_engine
        self.gui = None
    
    def show_gui(self, parent=None):
        """Show rule management GUI"""
        if parent is None:
            parent = tk.Tk()
            parent.title("Firewall Rule Manager")
            parent.geometry("1000x600")
        
        self.gui = RuleManagementGUI(parent, self.rule_engine)
        return parent
    
    def get_rule_statistics(self) -> Dict[str, Any]:
        """Get rule statistics"""
        return self.rule_engine.get_rule_statistics()
