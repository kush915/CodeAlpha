\# CodeAlpha Basic Network Sniffer



\## Project Overview



The Basic Network Sniffer is a Python-based network monitoring tool developed for the CodeAlpha Cyber Security Internship.



It uses Scapy to capture and analyze network packets on an authorized network interface.



\## Features



\- Live network packet capture

\- Source and destination IP addresses

\- TCP, UDP, ICMP, and DNS protocol identification

\- Source and destination port information

\- Packet length analysis

\- Limited hexadecimal payload preview

\- CSV report generation

\- Network interface listing



\## Technologies Used



\- Python

\- Scapy

\- Npcap

\- Windows

\- CSV



\## Installation



Install Python and Npcap first.



Create a virtual environment:



```powershell

python -m venv .venv

.\\.venv\\Scripts\\Activate.ps1

```



Install dependencies:



```powershell

python -m pip install -r requirements.txt

```



\## Usage



List available network interfaces:



```powershell

python sniffer.py --list-interfaces

```



Capture 100 packets:



```powershell

python sniffer.py --interface "Wi-Fi" --count 100

```



The interface name may differ on your computer. Use the exact name displayed by the interface-list command.



\## Output



Captured packet information is displayed in the terminal and saved to a CSV report.



\## Security Notice



Use this tool only on networks you own or have permission to monitor. Do not publish packet captures or sensitive network information.



\## Internship Details



Organization: CodeAlpha



Domain: Cyber Security



Task: Task 1 - Basic Network Sniffer



\## Project Status



Run and verify the project on your Windows system before marking testing as complete.

