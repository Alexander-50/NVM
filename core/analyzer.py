def assign_risk(score):
    if score is None:
        return "NONE"
    score = float(score)
    if score >= 9.0:
        return "CRITICAL"
    if score >= 7.0:
        return "HIGH"
    if score >= 4.0:
        return "MEDIUM"
    if score >= 0.1:
        return "LOW"
    return "NONE"

def analyze_vulnerabilities(cpe_results, all_vulnerabilities):
    final_results = {}
    max_risk_score = 0.0

    for port, info in cpe_results.items():
        vulns = all_vulnerabilities.get(port, [])
        port_max_cvss = 0.0
        
        for vuln in vulns:
            score = vuln.get('cvss_v3')
            if score and score > port_max_cvss:
                port_max_cvss = score

        risk_level = assign_risk(port_max_cvss)
        
        if port_max_cvss > max_risk_score:
            max_risk_score = port_max_cvss

        final_results[port] = {
            "port": port,
            "service": info['service'],
            "version": info['version'],
            "cpe": info['cpe'],
            "risk": risk_level,
            "vulnerabilities": vulns
        }

    overall_risk = assign_risk(max_risk_score)
    
    return overall_risk, final_results