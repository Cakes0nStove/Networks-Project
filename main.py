from discover import discover_hosts
from operating_system import nmap_scan_with_os
from nse_scripts import vul_scanner, save_scan
import ipaddress
import sys
from ai_overview import ai_overview

if __name__ == "__main__":
    networkip= input('input your network ip--->  ')
    network = ipaddress.ip_network(networkip, strict=True)
    live_hosts = discover_hosts(network)
    print('would you like to see more?')
    response= input('y/n -->  ')
    if response == 'n':
        print('goodbye ◝(ᵔᗜᵔ)◜')
        sys.exit()
    host_input = input('Which ip address would you like to scan?\nInput here-->  ')
    scan_type = input("Input either 1 or 2 for: a soft(1) or aggressive scan(2)? ").lower()
    nmap_scan_with_os(host_input, port_range='1-1024', scan_type=scan_type)
    save_scan()
    ai_overview()
