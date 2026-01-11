import nmap
import json 
from datetime import datetime

# this function uses nmap NSE scripts in order to provide a vulnerability scan 
# on a desired host.

def vul_scanner():
    nm = nmap.PortScanner()
    host = input("Enter IP to run vulnerability scan: ")

    print("\nExecuting vulnerability scan...\n")

    try:    #executes a vulnerability script
        nm.scan(hosts=host, arguments='-sV --script vuln')

        if host not in nm.all_hosts():
            print(f"{host}: not found in results")
            return None, None
#lets us know if the ip address input is invalid/not found.

        print(f"Host: {host}")
        print(f"State: {nm[host].state()}")
#puts the data into a Json ready structure
        scan_data = {
            "host": host,
            "state": nm[host].state(),
            "timestamp": datetime.utcnow().isoformat(),
            "ports": []
        }
        #loops through protocals and ports and stores per port data into the scan_data
        for proto in nm[host].all_protocols():
            for port in sorted(nm[host][proto].keys()):
                svc = nm[host][proto][port]
                scan_data["ports"].append({
                    "protocol": proto,
                    "port": port,
                    "service": svc.get("name"),
                    "state": svc.get("state"),
                    "scripts": svc.get("script", {}),
                    "fingerprints": svc.get("fingerprint-strings", {})
                })
                scripts = svc.get("script", {})
                print(f"\nPort {port}/{proto} ({svc.get('name','')})")
                #pritn sthe NSC vulenerbailtiy script raw data 
                if scripts:
                    print("  NSE Script Results:")
                    for sid, out in scripts.items():
                        print(f"\n    [{sid}]")
                        print(f"    {out}")
                else:
                    print("  No vulnerabilities detected")

                # -tries to vget raw fingerprint scipts if NMAP collects them
                fp = svc.get("fingerprint-strings", {})
                if fp:
                    print("  Fingerprint strings:")
                    for probe, response in fp.items():
                        print(f"\n    {probe}:")
                        print(f"      {response}")
#returns the results so that it can be used to calucalte the risk
        return nm, host, scan_data

    except Exception as e:
        print(f"Error: {e}")
        return None, None

#calcuates the risk based off the amount of open ports 
# and it increases the core if NSE script returns aanything  and if CVE are present 
# then three more points are added.  
def calculate_risk(nm, host):
    score = 0
    reasons = []

    open_ports = sum(len(nm[host][p]) for p in nm[host].all_protocols())
    score += min(open_ports, 4)
    reasons.append(f"{open_ports} open ports")

    critical = False
    for proto in nm[host].all_protocols():
        for svc in nm[host][proto].values():
            if svc.get("script"):
                score += 2
                reasons.append("Vulnerabilities detected")
                if "vulners" in svc["script"]:
                    critical = True

    if critical:
        score += 3
        reasons.append("Critical CVEs present")
#the maximum mark is out of 10
    return min(score, 10), reasons
# the scan is than saved in a JSON
def save_scan():
    nm, host, scan_data = vul_scanner()

    if nm and host:
        score, reasons = calculate_risk(nm, host)

        scan_data["risk_assessment"] = {
            "score": score,
            "level": (
                "Low" if score <= 2 else
                "Medium" if score <= 5 else
                "High" if score <= 8 else
                "Critical"
            ),
            "reasons": reasons
        }

        filename = f"{host}_vuln_scan.json"
        with open(filename, "w", encoding="utf-8") as f:
            json.dump(scan_data, f, indent=4)

        print(f"\nResults saved to {filename}")

