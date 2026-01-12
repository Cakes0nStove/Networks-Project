

import nmap
from LANmanager import lan_manager
from traceroute import get_traceroute_hops


def nmap_scan_with_os(host, port_range='1-1024', scan_type='1'):
    nm = nmap.PortScanner() #creates nmap scanner object
    try:
        # there are two types of scans, soft or aggressive, soft provides a quicker and less
        # detailed scan compared to aggressive.

        # The aggressive scan includes:
        # - host static method
        # - port information
        # - OS detection
        # - get_traceroute_hops
        # -SMB/LAN details

        if scan_type == '1':
            port_range = '1-10'
            arguments = '-sV'
            nm.scan(host, ports=port_range, arguments=arguments)
            print(f"Host: {host}")
            print(f"State: {nm[host].state()}")

            for proto in nm[host].all_protocols():
                print(f"\nProtocol: {proto}")

                for port in sorted(nm[host][proto].keys()):
                    service = nm[host][proto][port]
                    print(f"Port: {port}\tState: {service['state']}")

            return
        
        elif scan_type == '2':
            port_range = '1-1024'#aggressive scans for a larger port range.
            arguments = '-A'
        else:
            raise ValueError("scan_type must be 'soft' or 'aggressive'")

        nm.scan(host, ports=port_range, arguments=arguments)

        if host not in nm.all_hosts():
            print(f"Host {host} not found in scan results")
            return
        
        print(f"Host: {host}")
        print(f"State: {nm[host].state()}")
        #gets the amc address
        addresses = nm[host].get('addresses', {})
        mac = addresses.get('mac')

        if mac:
            print(f"MAC Address: {mac}")
            vendor = nm[host].get('vendor', {}).get(mac)
            if vendor:
                print(f"Vendor: {vendor}")
        else:
            print("MAC Address: Not available")
        #provides matches to operating system type
        if 'osmatch' in nm[host]:
            print("\nOperating Systems:")
            for os in nm[host]['osmatch']:
                print(f" - {os['name']} (accuracy: {os['accuracy']}%)")
        else:
            print("\nno OS information found ")

        # Loops through detected ports for the protocol
        for proto in nm[host].all_protocols():
            print(f"\nProtocol: {proto}")
            #displays the port state, service name and version
            for port in sorted(nm[host][proto].keys()):
                service = nm[host][proto][port]
                print(f"Port: {port}\tState: {service['state']}\tService: {service.get('name', '')} {service.get('version', '')}")
        #attempts to find the type of device which nmap compares too a database of fingerprints.
        if 'osclass' in nm[host]:
            print('finding device type')
            for osclass in nm[host]['osclass']:
                dtype = osclass.get('type')
                if dtype:
                    print(f"Device type: {dtype}")
        else:
            print("Device type: Not identified by OS fingerprinting")


        hops = get_traceroute_hops(nm, host)
        if not hops:
            print("\nTraceroute: Not available in XML output")
        else:
            print("\nTraceroute:")
            for hop in hops:
                print(f"  {hop['ttl']}\t{hop['ip']}\t{hop['rtt']} ms")

        lan_manager(host)

    except Exception as e:
        print(f"Error: {e}")

