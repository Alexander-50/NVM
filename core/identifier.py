import re

CPE_MAPPINGS = {
    "openssh": ("openbsd", "openssh"),
    "ssh": ("openbsd", "openssh"),
    "apache": ("apache", "http_server"),
    "http": ("apache", "http_server"),
    "mysql": ("oracle", "mysql"),
    "nginx": ("nginx", "nginx"),
}

TOKEN_SPLIT_REGEX = re.compile(r"[\s/\-_:;(),]+")


def clean_version_string(raw_version, service):
    if not raw_version:
        return None

    raw_version = raw_version.lower()

    if 'ssh' in service.lower():
        match = re.search(r'openssh[_\-]?([\d\.]+p?\d?)', raw_version)
        if match:
            return match.group(1)

    if 'apache' in service.lower() or 'http' in service.lower():
        match = re.search(r'apache\/?([\d\.]+)', raw_version)
        if match:
            return match.group(1)

    match = re.search(r'[\d\.\-]+\w*', raw_version)
    return match.group(0) if match else None


def map_to_cpe(raw_service, raw_version, port_num):
    if not raw_service:
        return None

    # tokenized matching rather than substring
    tokens = [t for t in TOKEN_SPLIT_REGEX.split(raw_service.lower()) if t]

    clean_version = None
    if raw_version and raw_version != "unknown":
        clean_version = clean_version_string(raw_version, raw_service)

    for key, (vendor, product) in CPE_MAPPINGS.items():
        if key in tokens:
            base_cpe = f"cpe:2.3:a:{vendor}:{product}"
            if clean_version:
                return f"{base_cpe}:{clean_version}"

            # If you want to force a demo fallback version for ssh port 22, you may:
            # if port_num == 22 and 'ssh' in tokens:
            #     return f"{base_cpe}:5.3"
            return base_cpe

    return None


def identify_cpes(open_ports_data):
    results = {}
    for port, info in open_ports_data.items():

        banner = info.get('banner')
        if info.get('service') == "banner_grabbed" and banner:
            # pick first non-empty token as service
            service_name = (banner.split()[0] if banner.split() else banner)
        else:
            service_name = info.get("service", "")

        version_str = info.get("version", "")

        cpe_string = map_to_cpe(service_name, version_str, port)

        results[port] = {
            "service": info.get("service"),
            "version": info.get("version"),
            "banner": banner,
            "cpe": cpe_string
        }
    return results
