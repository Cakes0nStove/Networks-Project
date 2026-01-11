
import nmap
import ipaddress
import json 

# takes a network range as an input and tries to discover alive hosts, the results
# are than saved into a JSON file and a list of live ip addresses are returned.
def discover_hosts(network):
    nm = nmap.PortScanner()
    print(f"\nDiscovering devices on: {network}\n")

    try:
        nm.scan(hosts=str(network), arguments='-sn')
        live_hosts = [host for host in nm.all_hosts() if nm[host].state() == 'up']

        discover_data ={
            "network": str(network),
            "live_hosts": live_hosts
        }
        
        print(f"Devices found: {len(live_hosts)}\n")
        for host in live_hosts:
            print(f" {host}")
#saves the data into a json file
        filename = f"live_hosts.json"
        with open(filename, "w", encoding="utf-8") as f:
            json.dump(discover_data, f, indent=4)

        print(f"\nResults saved to {filename}")
        return live_hosts

    except Exception as e:
        print(f"Error discovering network: {e}")
        return []


