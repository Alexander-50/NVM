def assign_risk(score):
    # Accept None gracefully
    try:
        if score is None:
            return "NONE"
        score = float(score)
    except Exception:
        return "NONE"

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
        vulns = all_vulnerabilities.get(port, []) or []
        port_max_cvss = 0.0

        for vuln in vulns:
            score = vuln.get('cvss_v3')
            try:
                if score is not None:
                    s = float(score)
                    if s > port_max_cvss:
                        port_max_cvss = s
            except Exception:
                # ignore unparsable scores
                continue

        risk_level = assign_risk(port_max_cvss)

        if port_max_cvss > max_risk_score:
            max_risk_score = port_max_cvss

        final_results[port] = {
            "port": port,
            "service": info.get('service'),
            "version": info.get('version'),
            "cpe": info.get('cpe'),
            "risk": risk_level,
            "vulnerabilities": vulns
        }

    overall_risk = assign_risk(max_risk_score)

    return overall_risk, final_results
