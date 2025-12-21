import tkinter as tk
from tkinter import messagebox, ttk
import json
import os

class ThreatLogWindow:
    def __init__(self, root):
        self.root = root
        self.root.title("Threat Log")

        # Treeview to display logs in a table-like format
        self.tree = ttk.Treeview(root, columns=("Attack", "Timestamp", "Source IP", "Destination IP", "Protocol", "Source Port", "Dest Port", "Payload Preview"), show="headings")
        self.tree.pack(pady=10, padx=10, expand=True, fill=tk.BOTH)

        # Define column headings
        for col in self.tree["columns"]:
            self.tree.heading(col, text=col)

        # Add a button to clear the logs
        self.clear_button = tk.Button(root, text="Clear All", command=self.clear_logs)
        self.clear_button.pack(pady=10)

        # Create a context menu for right-click
        self.context_menu = tk.Menu(root, tearoff=0)
        self.context_menu.add_command(label="Block Source IP", command=self.block_ip)

        # Bind right-click event to show the context menu
        self.tree.bind("<Button-3>", self.show_context_menu)

        # Load and display the log entries
        self.load_logs()

    def load_logs(self):
        """ Load and display the logged threats """
        try:
            with open('threat_log.txt', 'r') as log_file:
                logs = log_file.readlines()
                for log in logs:
                    try:
                        log_data = json.loads(log)
                        attack = log_data.get('attack', "N/A")
                        timestamp = log_data.get('timestamp', "N/A")
                        source_ip = log_data.get('source_ip', "N/A")
                        destination_ip = log_data.get('destination_ip', "N/A")
                        protocol = log_data.get('protocol', "N/A")
                        source_port = log_data.get('source_port', "N/A")
                        dest_port = log_data.get('dest_port', "N/A")
                        payload_preview = log_data.get('payload_preview', "No Payload")[:50]  # Limit to first 50 chars

                        # Insert a row in the treeview for each log entry
                        self.tree.insert("", "end", values=(attack, timestamp, source_ip, destination_ip, protocol, source_port, dest_port, payload_preview))
                    except json.JSONDecodeError:
                        continue  # Skip any invalid log lines
        except FileNotFoundError:
            messagebox.showwarning("Warning", "Log file not found.")

    def clear_logs(self):
        """ Clear all logs from the file and refresh the treeview """
        try:
            # Clear the log file
            open('threat_log.txt', 'w').close()  # This will overwrite the log file with nothing

            # Clear the content in the treeview
            for item in self.tree.get_children():
                self.tree.delete(item)

            messagebox.showinfo("Info", "All logs cleared successfully!")
        except Exception as e:
            messagebox.showerror("Error", f"Failed to clear logs: {e}")

    def show_context_menu(self, event):
        """ Display the right-click context menu """
        # Get the selected item
        selected_item = self.tree.selection()
        if selected_item:
            # Get the Source IP of the selected row
            row_values = self.tree.item(selected_item, "values")
            self.selected_ip = row_values[2]  # Source IP is in the 3rd column
            # Popup the context menu at the cursor position
            self.context_menu.post(event.x_root, event.y_root)

    def block_ip(self):
        """ Block the Source IP by calling an external blocking function or implementing the block """
        if hasattr(self, 'selected_ip') and self.selected_ip:
            ip_to_block = self.selected_ip
            # Show confirmation dialog before blocking
            if messagebox.askyesno("Confirm Block", f"Are you sure you want to block IP address {ip_to_block}?"):
                self.block_ip_system(ip_to_block)
            else:
                messagebox.showinfo("Info", "IP block operation canceled.")
        else:
            messagebox.showerror("Error", "No IP selected to block.")

    def block_ip_system(self, ip_address):
        """ System function to block IP address on the network """
        try:
            # Use iptables on Linux/macOS or netsh on Windows
            if os.name == 'posix':  # For Linux/macOS
                os.system(f"sudo iptables -A INPUT -s {ip_address} -j DROP")
                messagebox.showinfo("Blocked", f"IP address {ip_address} has been blocked successfully.")
            elif os.name == 'nt':  # For Windows
                # Windows requires admin permissions for netsh command
                command = f"netsh advfirewall firewall add rule name=\"Block {ip_address}\" dir=in action=block remoteip={ip_address}"
                result = os.system(command)
                if result == 0:
                    messagebox.showinfo("Blocked", f"IP address {ip_address} has been blocked successfully.")
                else:
                    messagebox.showerror("Error", f"Failed to block IP {ip_address}. Make sure you are running as administrator.")
            else:
                messagebox.showerror("Error", "Unsupported OS for blocking IP.")
        except Exception as e:
            messagebox.showerror("Error", f"Failed to block IP: {e}")

