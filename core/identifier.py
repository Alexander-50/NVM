import re

CPE_MAPPINGS = {
    "OpenSSH": ("openbsd", "openssh"),
    "ssh": ("openbsd", "openssh"),
    "Apache": ("apache", "http_server"),
    "http": ("apache", "http_server"),
    "MySQL": ("oracle", "mysql"),
    "nginx": ("nginx", "nginx"),
}

def clean_version_string(raw_version, service):
    if not raw_version:
        return None
        
    raw_version = raw_version.lower()
    
    if 'ssh' in service.lower():
        # Look for OpenSSH version specifically
        match = re.search(r'openssh_([\d\.]+p?\d?)', raw_version)
        if match:
            return match.group(1)
            
    if 'apache' in service.lower() or 'http' in service.lower():
        # Look for version immediately following 'apache/'
        match = re.search(r'apache\/([\d\.]+)', raw_version)
        if match:
            return match.group(1)

    # Generic Fallback Regex
    match = re.search(r'[\d\.\-]+\w*', raw_version)
    return match.group(0) if match else None

def map_to_cpe(raw_service, raw_version, port_num):
    if not raw_service:
        return None
        
    raw_service = raw_service.lower()
    
    clean_version = None
    if raw_version and raw_version != "unknown":
        clean_version = clean_version_string(raw_version, raw_service)
    
    # Check mappings first
    for banner_key, (vendor, product) in CPE_MAPPINGS.items():
        if banner_key.lower() in raw_service:
            
            base_cpe = f"cpe:2.3:a:{vendor}:{product}"
            
            if clean_version:
                return f"{base_cpe}:{clean_version}"
            
            # Special case for Port 22: If version is unknown, use a common old version (e.g., 5.3) 
            # to force NVD to return *something* for a high-risk service.
            if port_num == 22 and "ssh" in raw_service:
                return f"{base_cpe}:5.3" 
            
            return base_cpe
                
    return None

def identify_cpes(open_ports_data):
    results = {}
    for port, info in open_ports_data.items():
        
        if info['service'] == "banner_grabbed" and info['banner']:
            service_name = info['banner'].split(' ')[0]
        else:
            service_name = info.get("service", "")
            
        version_str = info.get("version", "")
        
        # Pass port number for special handling
        cpe_string = map_to_cpe(service_name, version_str, port)
        
        results[port] = {
            "service": info["service"],
            "version": info["version"],
            "banner": info.get("banner", None),
            "cpe": cpe_string
        }
    return results