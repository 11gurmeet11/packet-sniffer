import sys
import threading
from scapy.all import sniff, IP, TCP
import tkinter as tk
from tkinter import scrolledtext, messagebox

# Output file
OUTPUT_FILE = "packet_sniffer_results.txt"

class PacketSnifferGUI:
    def __init__(self, root):
        self.root = root
        self.root.title("Packet Sniffer GUI")
        self.root.geometry("700x500")
        self.root.resizable(False, False)

        # Title label
        tk.Label(root, text="TCP Packet Sniffer", font=("Arial", 16, "bold")).pack(pady=10)

        # Scrolled text area for displaying captured packets
        self.log_area = scrolledtext.ScrolledText(root, wrap=tk.WORD, width=85, height=25, font=("Consolas", 10))
        self.log_area.pack(padx=10, pady=10)
        self.log_area.config(state=tk.DISABLED)

        # Start Sniffing button
        self.start_button = tk.Button(root, text="Start Sniffing", command=self.start_sniffing, bg="green", fg="white", font=("Arial", 12))
        self.start_button.pack(pady=5)

    def log_packet(self, packet):
        if packet.haslayer(TCP) and packet.haslayer(IP):
            src_ip = packet[IP].src
            dst_ip = packet[IP].dst
            src_port = packet[TCP].sport
            dst_port = packet[TCP].dport
            payload = str(bytes(packet[TCP].payload))

            log_entry = (
                f"Source IP      : {src_ip}\n"
                f"Destination IP : {dst_ip}\n"
                f"Source Port    : {src_port}\n"
                f"Dest Port      : {dst_port}\n"
                f"Payload        : {payload[:60]}...\n"
                f"{'-'*50}\n"
            )

            # Update text area
            self.log_area.config(state=tk.NORMAL)
            self.log_area.insert(tk.END, log_entry)
            self.log_area.yview(tk.END)
            self.log_area.config(state=tk.DISABLED)

            # Save to file
            with open(OUTPUT_FILE, 'a') as f:
                f.write(log_entry)

    def start_sniffing(self):
        self.start_button.config(state=tk.DISABLED)
        try:
            thread = threading.Thread(target=self.sniff_packets)
            thread.daemon = True
            thread.start()
        except PermissionError:
            messagebox.showerror("Permission Denied", "Run this script with administrative privileges.")

    def sniff_packets(self):
        try:
            sniff(filter="tcp", prn=self.log_packet, store=0, count=10)
            messagebox.showinfo("Done", f"Sniffing complete. Results saved to {OUTPUT_FILE}")
        except Exception as e:
            messagebox.showerror("Error", str(e))
        finally:
            self.start_button.config(state=tk.NORMAL)

# Main execution
if __name__ == "__main__":
    try:
        root = tk.Tk()
        app = PacketSnifferGUI(root)
        root.mainloop()
    except KeyboardInterrupt:
        print("Program interrupted by user.")
