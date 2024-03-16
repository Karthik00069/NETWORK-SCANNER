import nmap
import subprocess
import json
import socket
def resolve_dns(domain):
    try:
        ip_address = socket.gethostbyname(domain)
        return ip_address
    except socket.gaierror:
        print(f"Unable to resolve DNS for {domain}")
        return None

def nmap_scan(target):
    nm = nmap.PortScanner()
    nm.scan(hosts=target, arguments='-sV -O --script vulners')

    scan_results = []
    for host in nm.all_hosts():
        result = {
            "host": host,
            "state": nm[host].state(),
            "scan_info": nm[host].all_protocols(),
            "open_ports": []
        }
        for proto in nm[host].all_protocols():
            ports = nm[host][proto].keys()
            for port in ports:
                port_info = {
                    "port": port,
                    "state": nm[host][proto][port]['state'],
                    "service": nm[host][proto][port]['name'],
                    "version": nm[host][proto][port]['version'],
                    "vulnerabilities": []
                }
                if 'vulners' in nm[host][proto][port]:
                    vulnerabilities = nm[host][proto][port]['vulners']
                    for vuln_id in vulnerabilities:
                        vuln_details = vulnerabilities[vuln_id]
                        vuln_details['id'] = vuln_id
                        port_info["vulnerabilities"].append(vuln_details)
                result["open_ports"].append(port_info)
        scan_results.append(result)
    return scan_results

if __name__ == "__main__":
    input_target = input("Enter IP address or domain name: ")
    
    # Check if input is IP or DNS
    if input_target.replace('.', '').isnumeric():  # Numeric input (likely IP address)
        target_ip = input_target
    else:  # Non-numeric input (likely domain name)
        target_ip = resolve_dns(input_target)
    
    if target_ip:
        # Perform Nmap scan
        nmap_results = nmap_scan(target_ip)
        print("Nmap Scan Results:")
        print(json.dumps(nmap_results, indent=4))

    else:
        print("Invalid input. Please enter a valid IP address or domain name.")
