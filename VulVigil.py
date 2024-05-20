import nmap
import socket
import tkinter as tk
from tkinter import messagebox
import scapy.all as scapy

class VulnerabilityScanner:
    def __init__(self):
        self.root = tk.Tk()
        self.create_widgets()


    def create_widgets(self):
        self.hostname_label = tk.Label(self.root, text="Enter the hostname (e.g., example.com):")
        self.hostname_label.pack()
        self.hostname_entry = tk.Entry(self.root, width=50)
        self.hostname_entry.pack()

        self.scan_button = tk.Button(self.root, text="Start Scan", command=self.start_scan)
        self.scan_button.pack()

        self.scanning_percentage_label = tk.Label(self.root, text="Scanning percentage: 0%")
        self.scanning_percentage_label.pack()

        self.results_text = tk.Text(self.root, width=80, height=20)
        self.results_text.pack()

        self.port_label = tk.Label(self.root, text="Enter the port number:")
        self.port_label.pack()
        self.port_entry = tk.Entry(self.root, width=50)
        self.port_entry.pack()

        self.vuln_button = tk.Button(self.root, text="Check Vulnerabilities", command=self.check_vulnerabilities)
        self.vuln_button.pack()

        self.close_port_button = tk.Button(self.root, text="Close Port", command=self.close_port)
        self.close_port_button.pack()

    def start_scan(self):
        self.results_text.delete(1.0, tk.END)  # Clear the text area
        self.scanning_percentage = 0
        self.update_scanning_percentage()

        hostname = self.hostname_entry.get()
        ip_address = socket.gethostbyname(hostname)

        scanner = nmap.PortScanner()
        scanner.scan(ip_address, arguments="-sS -T5 -n")

        self.results_text.insert(tk.END, f"Scan results for {hostname}:\n")

        for host in scanner.all_hosts():
            for proto in scanner[host].all_protocols():
                lport = scanner[host][proto].keys()
                for port in lport:
                    service = scanner[host][proto][port]['name']
                    self.results_text.insert(tk.END, f"  Port {port}/{proto} is open - {service}\n")

        self.results_text.insert(tk.END, "\n")

    def update_scanning_percentage(self):
        self.scanning_percentage += 10  # Increment the percentage
        self.scanning_percentage_label.config(text=f"Scanning percentage: {self.scanning_percentage}%")
        if self.scanning_percentage < 100:
            self.root.after(100, self.update_scanning_percentage)  # Update every 100ms
        else:
            self.scanning_percentage_label.config(text="Scanning complete!")

    def check_vulnerabilities(self):
        try:
            port = self.port_entry.get()
            hostname = self.hostname_entry.get()
            ip_address = socket.gethostbyname(hostname)

            scanner = nmap.PortScanner()
            scanner.scan(ip_address, arguments="-sV -p " + port)

            if ip_address in scanner.all_hosts():
                script_results = scanner[ip_address]['tcp'][int(port)].get('script', {})

                vulnerabilities = self.check_vulnerabilities_for_port(script_results, port)

                self.results_text.insert(tk.END, f"\nVulnerabilities found for port {port}:\n")
                for vuln in vulnerabilities:
                    self.results_text.insert(tk.END, f"  {vuln['name']}\n")

        except Exception as e:
            messagebox.showerror("Error", str(e))

    def check_vulnerabilities_for_port(self, script_results, port):
        vulnerabilities = []

        if port == "80":
            if 'http-robots-txt' in script_results:
                vulnerabilities.append({"name": "HTTP Robots.txt File Disclosure"})
            if 'http-title' in script_results:
                vulnerabilities.append({"name": "HTTP Title Information Disclosure"})
            if 'http-php-version' in script_results:
                vulnerabilities.append({"name": "PHP Version Information Disclosure"})

        elif port in ["139", "445"]:
            if 'smb-os-discovery' in script_results:
                vulnerabilities.append({"name": "SMB OS Discovery"})
            if 'smb-vuln-ms10-054' in script_results:
                vulnerabilities.append({"name": "SMB MS10-054 Vulnerability"})
            if 'smb-vuln-ms10-061' in script_results:
                vulnerabilities.append({"name": "SMB MS10-061 Vulnerability"})



        elif port == "3306":
            if 'mysql-info' in script_results:
                vulnerabilities.append({"name": "MySQL Information Disclosure"})
            if 'mysql-vuln-cve2012-2122' in script_results:
                vulnerabilities.append({"name": "MySQL CVE-2012-2122 Vulnerability"})

        elif port == "3389":
            if 'rdp-vuln-ms12-020' in script_results:
                vulnerabilities.append({"name": "RDP MS12-020 Vulnerability"})

        else:
            vulnerabilities.append({"name": "Unknown Service"})

        return vulnerabilities

    def close_port(self):
        try:
            port = self.port_entry.get()
            ip_address = self.hostname_entry.get()

            # Create a Scapy packet to send to the target IP address
            packet = scapy.IP(dst=ip_address) / scapy.TCP(dport=int(port), flags="R")

            # Send the packet to close the port
            scapy.send(packet)

            messagebox.showinfo("Success", f"Closed port {port}")
        except Exception as e:
            messagebox.showerror("Error", str(e))

if __name__ == "__main__":
    scanner = VulnerabilityScanner()
    scanner.root.mainloop()



