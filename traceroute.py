import xml.etree.ElementTree as ET
#importing xlm element tree to parse XML data, this is because Nmap outputs the scan reswults in XML format and 
#nmap python library cant output the results.
import nmap

# creates a function and uses nmap scanner obkject and a target ip address
def get_traceroute_hops(nm, target_ip):
    xml = nm.get_nmap_last_output()
    # gets the raw xml format
    root = ET.fromstring(xml)
# parses the xml string and conerts it into an elemtn root object so we can  traverese the XML 

    for h in root.findall("host"):
#goes through every <host> in nmap xlm where each host represents a detected machine
        addr = h.find("address[@addrtype='ipv4']")
        if addr is None or addr.get("addr") != target_ip:
            continue
#looks for an <address> tag and checks if an iPv4 address exists and if it martches the target ip
        trace = h.find("trace")
        if trace is None:
            return []
#searhes the <trace> element inside the host as trace containd the traceroute hop information
        hops = []
        # gets the hop ddetails and interates through every <hop>
        for hop in trace.findall("hop"):
            #stores the hop and returns it as a dictonary
            hops.append({
                "ttl": hop.get("ttl"),
                "ip": hop.get("ipaddr"),
                "rtt": hop.get("rtt"),
            })
        return hops
#fallback return if nothing is found
    return []
