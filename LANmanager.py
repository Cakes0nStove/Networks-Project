import nmap
#LAN = Local Area Network
def lan_manager(host):
    nm = nmap.PortScanner()

    try:
        # checks if the host is up, tries to hsot discovery, ARP discovery and reverese DNS to
        #try and find the ip to a hostname
        nm.scan(hosts=host, arguments='-sn -PR -R')

        if host not in nm.all_hosts() or nm[host].state() != "up":
            print(f"{host}: unreachable right now (may be asleep/offline).")
            return
        #confirms if the target is up
        hostname = nm[host].hostname() or None
        #tries to get the hostname and prints not found if unsuccessful
        print(f"Hostname: {hostname if hostname else 'Not found'}")

        #attempts to get the uptime which is how long the system has been running for
        #and prints out the results
        nm.scan(hosts=host, ports="1-200", arguments='-O -Pn')

        uptime_info = nm[host].get("uptime", {})
        if uptime_info:
            seconds = uptime_info.get("seconds", "Unknown")
            lastboot = uptime_info.get("lastboot", "Unknown")
            print(f"Uptime: {seconds}s")
            print(f"Last boot: {lastboot}")
        else:
            print("Uptime: Not available")

        # checks server message block ports i.e SMB ports. The SMB protocal allows for file
        # and resource sharing between devices on a network.
        nm.scan(hosts=host, arguments='-Pn -p 139,445')
        #if nmap cannot produce a host entry it pritns out a message as the packets
        #could be filtered by a firewall
        if host not in nm.all_hosts():
            print(f"{host}: unresponsive to TCP probes.")
            return
#afterwarrds,it pulls the tcp results and extracts eac ports state
        tcp = nm[host].get('tcp', {})
        p139 = tcp.get(139, {}).get('state')
        p445 = tcp.get(445, {}).get('state')
        print(f"\nSMB Ports: 139={p139}, 445={p445}")

        if p139 != "open" and p445 != "open":
            print("SMB not open (filtered/closed) — cannot retrieve LAN Manager info.")
            return
        # if neitehr SMB port is open then SMB enumeration scrypt is no point.
        # 4) Run SMB scripts
        nm.scan(
            hosts=host,
            arguments='-Pn -p 139,445 --script smb-protocols,smb2-security-mode,smb-os-discovery,nbstat'
        )
        #runs and NSE scrypt, that tells us:
        # -SMB version supported by server
        # - SMB singing settings
        # - atemps to denfity domain, windows version
        # - NetBIOS name table info if avaialble.


        # if the enurmeration works contine but if not print this statement and return.
        scripts = nm[host].get("hostscript", [])
        if not scripts:
            print("\nSMB open but enumeration restricted (common on modern Windows).")
            return
# creates a dictionary with the different arguements with their outpit
        script_map = {s["id"]: s["output"] for s in scripts}

        # SMB signing, reads the smb3 security output and classifies it 
        sec = script_map.get("smb2-security-mode", "")
        print("\nSMB Security:")
        if "not required" in sec.lower():
            print("  Signing: Enabled")
        elif "required" in sec.lower():
            print("  Signing: Required")
        else:
            print("  Signing: Unknown")

        # SMB protocols, goes through line by line and pritns out its protocal version
        proto = script_map.get("smb-protocols", "")
        print("\nSMB Versions Supported:")
        found_any = False
        for line in proto.splitlines():
            line = line.strip()
            if line and line[0].isdigit():
                found_any = True
                print(f"  - SMB {line.replace(':', '.')}")
        if not found_any:
            print("  - Not reported")

        #print smb-os-discovery/nbstat if present
        for sid in ("smb-os-discovery", "nbstat"):
            out = script_map.get(sid)
            if out:
                print(f"\n[{sid}]")
                print(out)

    except Exception as e:
        print(f"Error: {e}")

# lan_manager('10.0.0.5')
