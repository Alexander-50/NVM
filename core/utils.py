def parse_ports(ports_str):
    ports = set()
    try:
        if not ports_str:
            return []
        parts = [p.strip() for p in ports_str.split(',') if p.strip()]
        for part in parts:
            if '-' in part:
                bounds = [b.strip() for b in part.split('-')]
                if len(bounds) != 2 or not bounds[0] or not bounds[1]:
                    print(f"[!] Invalid port range: {part}")
                    continue
                start, end = int(bounds[0]), int(bounds[1])
                if start > end:
                    start, end = end, start
                # clamp to valid TCP port range
                start = max(1, min(65535, start))
                end = max(1, min(65535, end))
                ports.update(range(start, end + 1))
            else:
                ports.add(int(part))
        return sorted(list(ports))
    except ValueError:
        print(f"[!] Error parsing ports: {ports_str}")
        return []
