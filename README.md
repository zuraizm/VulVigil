# VulVigil (Vulnerability Scanner Tool)
This is a GUI-based vulnerability scanner tool written in Python, using the nmap and scapy libraries. The tool allows users to scan a target host for open ports, identify potential vulnerabilities, and even close open ports.

# Introduction
This is a GUI-based vulnerability scanner tool written in Python, using the nmap and scapy libraries. The tool allows users to scan a target host for open ports, identify potential vulnerabilities, and even close open ports.

# Features
Scan a target host for open ports using nmap
Identify potential vulnerabilities for specific ports (e.g. HTTP, SMB, MySQL, RDP)
Close open ports using scapy
GUI interface for easy use

# Usage
Clone this repository and install the required libraries (nmap and scapy)
Run the vulnerability_scanner.py script
Enter the target hostname and port number (if desired)
Click the "Start Scan" button to begin the scan
Review the scan results for open ports and potential vulnerabilities
Click the "Check Vulnerabilities" button to identify specific vulnerabilities for a given port
Click the "Close Port" button to close an open port

# Limitations
This tool is for educational purposes only and should not be used to scan systems without permission
The vulnerability checks are limited to a few specific ports and services
The tool may not work correctly in all environments or with all versions of nmap and scapy

# Future Development
Add more vulnerability checks for additional ports and services
Improve the GUI interface for better usability
Add more advanced features, such as automated vulnerability exploitation
Contributing

If you'd like to contribute to this project, please fork the repository and submit a pull request with your changes. I'm open to suggestions and improvements!
