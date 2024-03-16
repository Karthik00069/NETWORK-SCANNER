import nmap
import netifaces
from scapy.all import ARP, Ether, srp

def get_local_ip():
    interfaces = netifaces.interfaces()
    for interface in interfaces:
        if interface != "lo":
            addresses = netifaces.ifaddresses(interface)
            if netifaces.AF_INET in addresses:
                return addresses[netifaces.AF_INET][0]['addr']
    return None

def scan_network(ip):
    arp_req_frame = Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=ip)
    ans, _ = srp(arp_req_frame, timeout=3, verbose=False)
    
    devices = []
    for _, rcv in ans:
        devices.append({'ip': rcv.psrc, 'mac': rcv.hwsrc})
    return devices

def get_vendor(mac):
    # You can implement a function to retrieve vendor information
    # from the MAC address using an online API or local database.
    # For demonstration, let's just return 'Unknown'.
    return 'Unknown'

def main():
    local_ip = get_local_ip()
    if local_ip:
        network_prefix = local_ip.rsplit('.', 1)[0] + '.0/24'
        devices = scan_network(network_prefix)
        
        print("IP\t\tMAC Address\t\tVendor")
        print("-" * 40)
        for device in devices:
            vendor = get_vendor(device['mac'])
            print(f"{device['ip']}\t{device['mac']}\t{vendor}")
    else:
        print("Failed to retrieve local IP address.")

if __name__ == "__main__":
    main()
