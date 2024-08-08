import tkinter as tk
from tkinter import ttk, scrolledtext, messagebox
from scapy.all import ARP, Ether, srp, wrpcap, sniff, Dot11Deauth, sendp, IP, TCP, get_if_list
import threading
import time
import socket
from collections import defaultdict

activity_log = defaultdict(list)

def get_device_name(ip):
    try:
        return socket.gethostbyaddr(ip)[0]
    except socket.herror:
        return "Unknown"

def scan_network(target_ip_range):
    arp = ARP(pdst=target_ip_range)
    ether = Ether(dst="ff:ff:ff:ff:ff:ff")
    packet = ether / arp
    result = srp(packet, timeout=5, verbose=0)[0]
    clients = []

    for sent, received in result:
        device_name = get_device_name(received.psrc)
        clients.append({"ip": received.psrc, "mac": received.hwsrc, "name": device_name})

    return clients

def save_to_pcap(clients, filename):
    packets = []
    for client in clients:
        arp = ARP(pdst=client["ip"], hwdst=client["mac"])
        ether = Ether(dst=client["mac"])
        packet = ether / arp
        packets.append(packet)

    wrpcap(filename, packets)
    messagebox.showinfo("Save to PCAP", f"Captured packets saved to {filename}")

def print_scan_results(clients, text_widget=None):
    output = "Available devices on the network:\n"
    output += "{:<16} {:<18} {:<}\n".format("IP", "MAC", "Device Name")
    for client in clients:
        output += "{:<16} {:<18} {:<}\n".format(client["ip"], client["mac"], client["name"])

    if text_widget:
        text_widget.delete(1.0, tk.END)
        text_widget.insert(tk.END, output)
    else:
        print(output)

def detect_activity(packet):
    if packet.haslayer(ARP):
        log_activity(packet[ARP].psrc, packet[ARP].hwsrc, "ARP activity")
    elif packet.haslayer(IP) and packet.haslayer(TCP):
        src_ip = packet[IP].src
        dst_ip = packet[IP].dst
        src_port = packet[TCP].sport
        dst_port = packet[TCP].dport
        log_activity(src_ip, packet[Ether].src, f"TCP packet: {src_ip}:{src_port} -> {dst_ip}:{dst_port}")

def log_activity(ip, mac, activity):
    timestamp = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime())
    device_name = get_device_name(ip)
    activity_log[ip].append({"time": timestamp, "mac": mac, "name": device_name, "activity": activity})
    activity_log[ip] = [entry for entry in activity_log[ip] if time.time() - time.mktime(time.strptime(entry["time"], "%Y-%m-%d %H:%M:%S")) <= 86400]

def print_activity_log(text_widget=None):
    output = "Internet usage in the last 24 hours:\n"
    for ip, activities in activity_log.items():
        for activity in activities:
            output += f"{activity['time']} - {ip} ({activity['name']}): {activity['activity']}\n"

    if text_widget:
        text_widget.delete(1.0, tk.END)
        text_widget.insert(tk.END, output)
    else:
        print(output)

def monitor_network_activity(interface, text_widget=None):
    if text_widget:
        text_widget.insert(tk.END, "Monitoring network activity...\n")
    sniff(iface=interface, prn=detect_activity, store=0)

def start_monitoring(interface, text_widget=None):
    monitor_thread = threading.Thread(target=monitor_network_activity, args=(interface, text_widget))
    monitor_thread.start()

def disconnect_device(target_mac, gateway_mac, interface):
    dot11 = Dot11Deauth(addr1=target_mac, addr2=gateway_mac, addr3=gateway_mac)
    sendp(dot11, iface=interface, count=100, inter=0.1, verbose=1)
    messagebox.showinfo("Disconnect Device", f"Sent deauthentication packets to {target_mac}")

def create_ui():
    root = tk.Tk()
    root.title("Optweb Network Scanner")
    
    notebook = ttk.Notebook(root)
    notebook.pack(expand=1, fill='both')

    # Network Scan Tab
    tab1 = ttk.Frame(notebook)
    notebook.add(tab1, text='Network Scan')

    ip_label = tk.Label(tab1, text="Enter IP range (e.g., 192.168.1.1/24):")
    ip_label.pack(pady=5)
    ip_entry = tk.Entry(tab1, width=30)
    ip_entry.pack(pady=5)
    
    scan_button = tk.Button(tab1, text="Scan Network", command=lambda: print_scan_results(scan_network(ip_entry.get()), scan_result_text))
    scan_button.pack(pady=5)

    scan_result_text = scrolledtext.ScrolledText(tab1, width=80, height=20)
    scan_result_text.pack(pady=5)
    
    save_button = tk.Button(tab1, text="Save to PCAP", command=lambda: save_to_pcap(scan_network(ip_entry.get()), "network_scan.pcap"))
    save_button.pack(pady=5)

    # Network Monitor Tab
    tab2 = ttk.Frame(notebook)
    notebook.add(tab2, text='Network Monitor')

    interface_label = tk.Label(tab2, text="Select Network Interface:")
    interface_label.pack(pady=5)
    
    interfaces = get_if_list()
    interface_var = tk.StringVar(value=interfaces[0])
    interface_menu = tk.OptionMenu(tab2, interface_var, *interfaces)
    interface_menu.pack(pady=5)
    
    monitor_text = scrolledtext.ScrolledText(tab2, width=80, height=20)
    monitor_text.pack(pady=5)
    
    monitor_button = tk.Button(tab2, text="Start Monitoring", command=lambda: start_monitoring(interface_var.get(), monitor_text))
    monitor_button.pack(pady=5)

    activity_log_button = tk.Button(tab2, text="Show Activity Log", command=lambda: print_activity_log(monitor_text))
    activity_log_button.pack(pady=5)

    # Disconnect Device Tab
    tab3 = ttk.Frame(notebook)
    notebook.add(tab3, text='Disconnect Device')

    mac_label = tk.Label(tab3, text="Enter Target MAC Address:")
    mac_label.pack(pady=5)
    mac_entry = tk.Entry(tab3, width=30)
    mac_entry.pack(pady=5)
    
    gateway_label = tk.Label(tab3, text="Enter Gateway MAC Address:")
    gateway_label.pack(pady=5)
    gateway_entry = tk.Entry(tab3, width=30)
    gateway_entry.pack(pady=5)
    
    disconnect_button = tk.Button(tab3, text="Disconnect Device", command=lambda: disconnect_device(mac_entry.get(), gateway_entry.get(), interface_var.get()))
    disconnect_button.pack(pady=5)

    root.mainloop()

def main():
    while True:
        print("Network Monitoring System")
        print("1. Scan Network")
        print("2. Save to PCAP")
        print("3. Start Monitoring")
        print("4. Show Activity Log")
        print("5. Disconnect Device")
        print("6. Exit")
        choice = input("Enter your choice: ")

        if choice == '1':
            ip_range = input("Enter IP range (e.g., 192.168.1.1/24): ")
            clients = scan_network(ip_range)
            print_scan_results(clients)
        elif choice == '2':
            ip_range = input("Enter IP range (e.g., 192.168.1.1/24): ")
            clients = scan_network(ip_range)
            filename = input("Enter filename to save (e.g., network_scan.pcap): ")
            save_to_pcap(clients, filename)
        elif choice == '3':
            interface = input("Enter network interface: ")
            start_monitoring(interface)
        elif choice == '4':
            print_activity_log()
        elif choice == '5':
            target_mac = input("Enter target MAC address: ")
            gateway_mac = input("Enter gateway MAC address: ")
            interface = input("Enter network interface: ")
            disconnect_device(target_mac, gateway_mac, interface)
        elif choice == '6':
            break
        else:
            print("Invalid choice. Please try again.")

if __name__ == "__main__":
    print("Choose mode:")
    print("1. Command Line Interface (CLI)")
    print("2. Graphical User Interface (GUI)")
    mode = input("Enter your choice: ")

    if mode == '1':
        main()
    elif mode == '2':
        create_ui()
    else:
        print("Invalid choice. Please restart and select a valid mode.")
