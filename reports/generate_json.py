import json
import time

def create_json_report(overall_risk, final_results, target):
    report_data = {
        "scan_date": time.strftime("%Y-%m-%d %H:%M:%S"),
        "target": target,
        "overall_risk": overall_risk,
        "results": final_results
    }
    
    filename = f"NVM-Report-{target}.json"
    
    with open(f"reports/{filename}", 'w') as f:
        json.dump(report_data, f, indent=4)
        
    return filename