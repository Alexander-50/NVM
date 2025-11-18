import asyncio
import aiohttp
import json
import os
import time

# --- CONFIGURATION ---
NVD_API_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
CACHE_FILE = "data/cve_cache.json"

# Get API Key from environment
API_KEY = os.getenv("NVD_API_KEY")

# Rate Limiting Config
# With Key: 50 req / 30s (~0.6s delay) | Without Key: 5 req / 30s (~6.0s delay)
DELAY = 0.6 if API_KEY else 6.0
MAX_CONCURRENT_REQUESTS = 5  # Safety buffer to avoid overwhelming local network

async def load_cache():
    if not os.path.exists(CACHE_FILE):
        return {}
    try:
        with open(CACHE_FILE, 'r') as f:
            return json.load(f)
    except (json.JSONDecodeError, IOError):
        return {}

def save_cache_sync(cache_data):
    """Saves cache synchronously (file I/O is fast enough to keep simple)"""
    os.makedirs(os.path.dirname(CACHE_FILE), exist_ok=True)
    try:
        with open(CACHE_FILE, 'w') as f:
            json.dump(cache_data, f, indent=4)
    except IOError:
        pass

def extract_cvss_score(metrics):
    """Extracts CVSS score handling NVD API 2.0 schema"""
    # Priority: V3.1 -> V3.0 -> V2.0
    if metrics.get('cvssMetricV31'):
        return metrics['cvssMetricV31'][0]['cvssData'].get('baseScore')
    if metrics.get('cvssMetricV30'):
        return metrics['cvssMetricV30'][0]['cvssData'].get('baseScore')
    if metrics.get('cvssMetricV2'):
        return metrics['cvssMetricV2'][0]['cvssData'].get('baseScore')
    return None

async def query_nvd_async(session, cpe_string, semaphore):
    """
    Queries NVD asynchronously with rate limiting.
    """
    params = {"cpeName": cpe_string}
    headers = {}
    
    # FIX: NVD requires 'apiKey' header, not Authorization
    if API_KEY:
        headers["apiKey"] = API_KEY

    async with semaphore:
        try:
            # Enforce rate limit delay before request
            await asyncio.sleep(DELAY) 
            
            async with session.get(NVD_API_URL, params=params, headers=headers, timeout=10) as response:
                if response.status == 404:
                    return [] # No CVEs found
                
                if response.status in [403, 429]:
                    print(f"[!] Rate limit hit for {cpe_string}. Slowing down...")
                    await asyncio.sleep(10) # Penalty wait
                    return None

                response.raise_for_status()
                data = await response.json()

                vulnerabilities = []
                if data.get('vulnerabilities'):
                    for vuln in data['vulnerabilities']:
                        cve = vuln['cve']
                        metrics = cve.get('metrics', {})
                        cvss_score = extract_cvss_score(metrics)
                        
                        vulnerabilities.append({
                            "id": cve.get('id'),
                            "description": cve['descriptions'][0]['value'],
                            "cvss_v3": cvss_score
                        })
                return vulnerabilities

        except aiohttp.ClientError as e:
            print(f"[!] Network error for {cpe_string}: {e}")
            return None
        except Exception as e:
            print(f"[!] Error processing {cpe_string}: {e}")
            return None

async def fetch_cves_async(cpe_results):
    """
    Main orchestrator for fetching CVEs
    """
    cache = await load_cache()
    all_vulns = {}
    tasks = []
    
    # Semaphore limits how many 'active' requests happen at once
    semaphore = asyncio.Semaphore(MAX_CONCURRENT_REQUESTS)

    async with aiohttp.ClientSession() as session:
        cpes_to_query = []
        
        # 1. check cache first
        for port, info in cpe_results.items():
            cpe = info.get("cpe")
            if not cpe:
                continue
            
            if cpe in cache:
                print(f"[*] Cache hit for {cpe}")
                all_vulns[port] = cache[cpe]
            else:
                cpes_to_query.append((port, cpe))

        # 2. Prepare async tasks for non-cached items
        if cpes_to_query:
            print(f"[*] Querying NVD for {len(cpes_to_query)} CPEs...")
            
            for port, cpe in cpes_to_query:
                # Create a task for each query
                task = query_nvd_async(session, cpe, semaphore)
                tasks.append((port, cpe, task))
            
            # 3. Run all tasks
            results = await asyncio.gather(*[t[2] for t in tasks])
            
            # 4. Process results
            for i, result in enumerate(results):
                port = tasks[i][0]
                cpe = tasks[i][1]
                
                if result is not None:
                    cache[cpe] = result
                    all_vulns[port] = result
        
        # Save updated cache
        save_cache_sync(cache)
        return all_vulns

# ---------------------------------------------------------
# COMPATIBILITY WRAPPER (Solves your ImportError)
# ---------------------------------------------------------
def fetch_cves(cpe_results):
    """
    Allows synchronous nvm.py to call async logic.
    Includes a Windows-specific fix for the event loop.
    """
    if os.name == 'nt':
        # FIX: Prevents 'RuntimeError: Event loop is closed' on Windows
        asyncio.set_event_loop_policy(asyncio.WindowsSelectorEventLoopPolicy())
        
    return asyncio.run(fetch_cves_async(cpe_results))

# --- TEST BLOCK ---
if __name__ == "__main__":
    mock_data = {80: {"cpe": "cpe:2.3:a:apache:http_server:2.4.49:*:*:*:*:*:*:*"}}
    print(json.dumps(fetch_cves(mock_data), indent=2))