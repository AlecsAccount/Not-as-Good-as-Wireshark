import tkinter as tk
from tkinter import scrolledtext, filedialog
from scapy.all import sniff, IP, TCP, UDP, DNS
from datetime import datetime
import threading

# Protocol map
PROTO_MAP = {1: "ICMP", 6: "TCP", 17: "UDP"}

def protocol_name(proto_num):
    return PROTO_MAP.get(proto_num, f"OTHER({proto_num})")

# GUI setup
root = tk.Tk()
root.title("Packet Sniffer")
root.configure(bg="#003300")  # Dark green background

text_area = scrolledtext.ScrolledText(root, bg="#002200", fg="#00FF00", font=("Consolas", 10))
text_area.pack(expand=True, fill='both')

# Open log file in append mode with UTF-8 encoding
log_file = open(f"packet_log_{datetime.now().strftime('%Y%m%d_%H%M%S')}.txt", "a", encoding="utf-8")

def log_message(msg):
    print(msg)  # Debug: Print to console
    text_area.insert(tk.END, msg + "\n")
    text_area.see(tk.END)
    log_file.write(msg + "\n")   # Save to file
    log_file.flush()             # Ensure it's written immediately

# Packet callback
def packet_callback(packet):
    if IP in packet:
        timestamp = datetime.now().strftime("%H:%M:%S")
        ip_src = packet[IP].src
        ip_dst = packet[IP].dst
        proto_num = packet[IP].proto
        proto = protocol_name(proto_num)

        sport = dport = "-"
        if TCP in packet:
            sport = packet[TCP].sport
            dport = packet[TCP].dport
        elif UDP in packet:
            sport = packet[UDP].sport
            dport = packet[UDP].dport

        log_message(f"[{timestamp}] {ip_src}:{sport} → {ip_dst}:{dport} ({proto})")

        if DNS in packet and packet.haslayer(DNS) and packet[DNS].qd:
            try:
                query = packet[DNS].qd.qname.decode()
                log_message(f"    └── DNS Query: {query}")
            except:
                pass

# Threaded sniffer to avoid freezing the GUI
def start_sniffing():
    sniff(filter="ip", prn=packet_callback, store=0)

# Launch sniffing in a background thread
threading.Thread(target=start_sniffing, daemon=True).start()

# Save log file via a button
def save_log():
    filename = filedialog.asksaveasfilename(defaultextension=".txt", filetypes=[("Text Files", "*.txt")])
    if filename:
        with open(filename, "w", encoding="utf-8") as f:
            f.write(text_area.get("1.0", tk.END))
        log_message(f"Log saved to {filename}")

# Handle window close and auto-save logs
def on_close():
    log_file.close()  # Close the log file to ensure all data is written
    root.destroy()  # Close the tkinter window

# Add Save Log button
save_button = tk.Button(root, text="Save Log", command=save_log, bg="#00FF00", fg="#003300", font=("Arial", 12))
save_button.pack(pady=10)

# Run GUI
root.protocol("WM_DELETE_WINDOW", on_close)  # Ensure proper cleanup on close
log_message("🛜 Sniffing... press Ctrl+C in console to exit")
root.mainloop()
