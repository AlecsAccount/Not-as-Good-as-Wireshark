Packet Sniffer GUI (Tkinter + Scapy)

This Python script provides a GUI-based packet sniffer using Tkinter for the interface and Scapy for network packet capture. It logs IP, TCP, UDP, and DNS traffic in real-time, displays it in a scrollable window, and saves logs to a file.



Features



Real-time packet capture with Scapy

GUI display of packets with green-on-dark theme

Supports TCP, UDP, IP, ICMP, and DNS query detection

Timestamped logging of source/destination IPs and ports

Auto-log to file with timestamped filename

Save log manually via a "Save Log" button

Runs sniffing in a background thread to keep the GUI responsive



Requirements

Python 3.7+



Libraries: tkinter (built-in), scapy

Install Scapy:

pip install scapy

Usage

Run the script:

python packet_sniffer_gui.py


A GUI window opens, and packets will be logged live.

Use the Save Log button to save the current log to a text file.

Close the window to automatically save and cleanup the default log file.



Example Output
🛜 Sniffing... press Ctrl+C in console to exit
[12:34:56] 192.168.1.5:443 → 192.168.1.10:12345 (TCP)
    └── DNS Query: example.com
[12:34:58] 192.168.1.5:- → 192.168.1.10:53 (UDP)



Notes & Limitations

Requires administrator/root privileges to sniff network packets.

Only IPv4 packets are logged (filter="ip").

DNS queries are parsed if present in the packet.

The GUI is thread-safe thanks to a background sniffing thread.

Logs are written live to a timestamped file and can also be saved manually.



Improvements

Added protocol mapping for ICMP/TCP/UDP

Threaded sniffing ensures GUI does not freeze

Auto-flush logs to file for real-time persistence

DNS query decoding for extra insights



License

Open-source; feel free to modify and use for personal or educational purposes.
