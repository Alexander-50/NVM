import socket
import concurrent.futures
from core import utils
import re

def parse_http_banner(banner):
    match = re.search(r'Server: (.*)', banner, re.IGNORECASE)
    if match:
        return match.group(1).strip()
    return None

def grab_banner(s):
    try:
        # Send a trigger request
        s.send(b'HEAD / HTTP/1.0\r\n\r\n')
        
        # Increase timeout to 2.0s to catch slow SSH banners
        s.settimeout(2.0)
        
        banner = s.recv(2048).decode('utf-8', errors='ignore').strip()
        
        if 'HTTP' in banner:
            clean_banner = parse_http_banner(banner)
            if clean_banner:
                return clean_banner
        
        return banner
    except:
        return None

def scan_single_port(target, port, timeout=2.0):
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(timeout)
            result = s.connect_ex((target, port))
            
            if result == 0:
                # Banner grab attempt
                banner = grab_banner(s)
                
                service = "unknown"
                version = "unknown"
                
                if banner:
                    service = "banner_grabbed" 
                    version = banner 
                else:
                    try:
                        service = socket.getservbyport(port)
                    except:
                        pass

                return port, {"service": service, "version": version, "banner": banner}
                
    except Exception:
        pass
    return None

def run_scan(target, ports_str, threads=50):
    ports = utils.parse_ports(ports_str)
    results = {}
    
    with concurrent.futures.ThreadPoolExecutor(max_workers=threads) as executor:
        future_to_port = {
            executor.submit(scan_single_port, target, port): port 
            for port in ports
        }
        
        for future in concurrent.futures.as_completed(future_to_port):
            data = future.result()
            if data:
                port_num, info = data
                results[port_num] = info
                
    return results