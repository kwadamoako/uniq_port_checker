# uniq_port_checker version 1.0 
# created by Kwadwo Amoako
# Please use responsibly...
# Software URL: https://github.com/kwadamoako/unique_port_checker/
# linkedin: https://www.linkedin.com/in/kwadwo-agyei-amoako/

import re
from tkinter import filedialog, Tk
from collections import defaultdict

def parse_nmap_results(nmap_output):
    """
    Parse Nmap scan results to extract IP addresses and their open ports.
    """
    ip_ports = defaultdict(list)
    ip_regex = re.compile(r'Nmap scan report for (.+?)\n(.*?)(?=\n\nNmap scan report|\Z)', re.DOTALL)
    port_regex = re.compile(r'(\d+)/(\w+)\s+open')

    matches = ip_regex.findall(nmap_output)
    for match in matches:
        ip = match[0]
        ports = port_regex.findall(match[1])
        for port, protocol in ports:
            ip_ports[ip].append((int(port), protocol))

    return ip_ports

def find_unique_ports(ip_ports, unique_percentage):
    """
    Identify ports that are open on a particular IP and occur fewer times compared to the rest.
    """
    port_count = defaultdict(int)
    ip_count = defaultdict(int)

    # Count occurrences of each unique port across all IPs
    for ports in ip_ports.values():
        for port, _ in ports:
            port_count[port] += 1

    # Count occurrences of each IP that has a port open
    for ip, ports in ip_ports.items():
        for port, _ in ports:
            ip_count[ip] += 1

    # Determine unique ports based on the percentage provided by the user
    unique_ports = set()
    threshold = len(ip_ports) * (unique_percentage / 100.0)
    for port, count in port_count.items():
        if count <= threshold:
            unique_ports.add(port)

    unique_ports_per_ip = {ip: [port for port, _ in ports if port in unique_ports] for ip, ports in ip_ports.items()}

    return unique_ports_per_ip

def select_file():
    root = Tk()
    root.withdraw()
    file_path = filedialog.askopenfilename()
    return file_path

def save_results_to_file(file_path, unique_ports):
    try:
        with open(file_path, 'w') as file:
            file.write("IPs with unique open ports:\n")
            for ip, ports in unique_ports.items():
                if ports:
                    file.write(f"IP: {ip} has unique open ports: {ports}\n")
        print(f"Results saved to {file_path}")
    except IOError:
        print("Error: Unable to save results.")

def run_program():
    file_path = select_file()
    if file_path:
        try:
            with open(file_path, 'r') as file:
                nmap_output = file.read()
        except IOError:
            print("Error: Unable to open file.")
        else:
            unique_percentage = float(input("Enter the percentage of unique ports to identify (e.g., 20): "))
            ip_ports = parse_nmap_results(nmap_output)
            unique_ports = find_unique_ports(ip_ports, unique_percentage)

            print("IPs with unique open ports:")
            for ip, ports in unique_ports.items():
                if ports:
                    print(f"IP: {ip} has unique open ports: {ports}")

            run_again = input("Do you want to run the program again? (yes/no): ").lower()
            if run_again == "yes" or run_again == "y":
                run_program()
            else:
                output_option = input("Do you want to save the results to a file? (yes/no): ").lower()
                if output_option == "yes" or output_option == "y":
                    output_file_path = input("Enter the path to save the results: ")
                    save_results_to_file(output_file_path, unique_ports)
    else:
        print("No file selected.")

if __name__ == "__main__":
    run_program()
