import tkinter as tk

def show_alert(threats, packet):
    """ Popup alert for detected threats, positioned in the top-left corner with a countdown timer. """
    popup = tk.Toplevel()
    popup.title("Threat Alert")
    popup.geometry("300x120+10+10")  # Top-left corner
    popup.configure(bg="grey")
    popup.lift()  # Ensure the popup is on top of other windows

    # Check for SYN Flood or DDoS
    special_alerts = [threat for threat in threats if threat['attack'] in ['SYN Flood', 'DDoS Attack']]
    suspicious_alerts = [threat for threat in threats if 'Suspicious' in threat['attack']]
    
    if special_alerts:
        # Custom message for SYN Flood and DDoS
        threat_text = "⚠️ Potential DDoS/SYN Flood Attack Detected!"
        label = tk.Label(popup, text=threat_text, 
                         font=("Arial", 12, "bold"), fg="white", bg="red")
        label.pack(expand=True, pady=10)

        # Add more details (optional)
        details_label = tk.Label(popup, text="Your system might be under heavy traffic.", 
                                 font=("Arial", 8, "bold"), fg="white", bg="red")
        details_label.pack(expand=True, pady=5)
    elif suspicious_alerts:
        # Custom message for Suspicious Behaviour (Anomaly Detection)
        threat_text = "⚠️ Suspicious Behaviour Detected!"
        label = tk.Label(popup, text=threat_text, 
                         font=("Arial", 12, "bold"), fg="black", bg="orange")
        label.pack(expand=True, pady=10)
        
        # Add source info
        src_info = suspicious_alerts[0].get('src', 'Unknown')
        details_label = tk.Label(popup, text=f"Source: {src_info}", 
                                 font=("Arial", 9), fg="black", bg="orange")
        details_label.pack(expand=True, pady=5)
    else:
        # Generic message for signature-based attacks
        threat_text = "\n".join([threat['attack'] for threat in threats])
        label = tk.Label(popup, text=f"⚠️ Threat Detected!\n{threat_text}", 
                         font=("Arial", 12, "bold"), fg="white", bg="red")
        label.pack(expand=True, pady=10)

    # Timer Progress Bar
    progress = tk.Canvas(popup, height=5, bg="lightgray", highlightthickness=0)
    progress.pack(fill="x")

    # Function to update progress bar and timer
    def update_progress(step=0, time_left=5):
        if step < 100:
            progress.delete("bar")
            progress.create_rectangle(0, 0, 3 * step, 5, fill="blue", tags="bar")
            popup.after(50, update_progress, step + 2, time_left - 1 if step % 20 == 0 else time_left)
        else:
            popup.destroy()

    update_progress()
    
    # Auto-close after 5 seconds
    popup.after(5000, popup.destroy)

    
