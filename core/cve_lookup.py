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
MAX_RETRIES = 3


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
    dirpath = os.path.dirname(CACHE_FILE) or '.'
    os.makedirs(dirpath, exist_ok=True)
    try:
        with open(CACHE_FILE, 'w') as f:
            json.dump(cache_data, f, indent=4)
    except IOError:
        pass


def extract_cvss_score(metrics):
    """Extracts CVSS score handling NVD API 2.0 schema"""
    # Priority: V3.1 -> V3.0 -> V2.0
    try:
        if metrics.get('cvssMetricV31'):
            return metrics['cvssMetricV31'][0]['cvssData'].get('baseScore')
        if metrics.get('cvssMetricV30'):
            return metrics['cvssMetricV30'][0]['cvssData'].get('baseScore')
        if metrics.get('cvssMetricV2'):
            return metrics['cvssMetricV2'][0]['cvssData'].get('baseScore')
    except Exception:
        return None
    return None


async def query_nvd_async(session, cpe_string, semaphore):
    """
    Queries NVD asynchronously with rate limiting and retries.
    Always returns a list (empty list means no CVEs or failed after retries).
    """
    params = {"cpeName": cpe_string}
    headers = {}

    if API_KEY:
        headers["apiKey"] = API_KEY

    async with semaphore:
        # Simple retry loop with exponential backoff
        for attempt in range(1, MAX_RETRIES + 1):
            try:
                # Enforce rate limit delay before request
                await asyncio.sleep(DELAY)

                async with session.get(NVD_API_URL, params=params, headers=headers, timeout=10) as response:
                    if response.status == 404:
                        return []  # No CVEs found

                    if response.status in [403, 429]:
                        # Rate limit / forbidden: wait a penalty and try again
                        print(f"[!] Rate limit/hit (status={response.status}) for {cpe_string}. Attempt {attempt}/{MAX_RETRIES}.")
                        await asyncio.sleep(5 * attempt)
                        continue

                    # For other non-2xx, raise to trigger retry
                    response.raise_for_status()
                    data = await response.json()

                    vulnerabilities = []
                    if data.get('vulnerabilities'):
                        for vuln in data['vulnerabilities']:
                            cve = vuln.get('cve', {}) or {}
                            # SAFE description extraction
                            descriptions = cve.get('descriptions', []) or []
                            desc = None
                            for d in descriptions:
                                if d.get('lang') == 'en' and d.get('value'):
                                    desc = d.get('value')
                                    break
                            if not desc and descriptions:
                                desc = descriptions[0].get('value')
                            if not desc:
                                desc = 'No description available.'

                            metrics = cve.get('metrics', {}) or {}
                            cvss_score = extract_cvss_score(metrics)

                            vulnerabilities.append({
                                "id": cve.get('id') or cve.get('CVE_data_meta', {}).get('ID'),
                                "description": desc,
                                "cvss_v3": cvss_score
                            })
                    return vulnerabilities

            except aiohttp.ClientResponseError as e:
                # 5xx & http errors; retry
                print(f"[!] HTTP Error for {cpe_string}: {e} (attempt {attempt})")
                await asyncio.sleep(2 * attempt)
                continue
            except aiohttp.ClientError as e:
                print(f"[!] Network/Client error for {cpe_string}: {e} (attempt {attempt})")
                await asyncio.sleep(2 * attempt)
                continue
            except asyncio.TimeoutError:
                print(f"[!] Timeout for {cpe_string} (attempt {attempt})")
                await asyncio.sleep(2 * attempt)
                continue
            except Exception as e:
                print(f"[!] Unexpected error processing {cpe_string}: {e} (attempt {attempt})")
                await asyncio.sleep(2 * attempt)
                continue

        # After retries: return empty list (treat as no CVEs found) — do not return None to avoid silent drops
        print(f"[!] Giving up on {cpe_string} after {MAX_RETRIES} attempts. Treating as zero CVEs.")
        return []


async def fetch_cves_async(cpe_results):
    """
    Main orchestrator for fetching CVEs
    """
    cache = await load_cache()
    all_vulns = {}
    tasks = []

    semaphore = asyncio.Semaphore(MAX_CONCURRENT_REQUESTS)

    async with aiohttp.ClientSession() as session:
        cpes_to_query = []

        # 1. check cache first
        for port, info in cpe_results.items():
            cpe = info.get("cpe")
            if not cpe:
                continue

            if cpe in cache:
                # cached value might be None or list; ensure list
                cached_val = cache.get(cpe) or []
                print(f"[*] Cache hit for {cpe}")
                all_vulns[port] = cached_val
            else:
                cpes_to_query.append((port, cpe))

        # 2. Prepare async tasks for non-cached items
        if cpes_to_query:
            print(f"[*] Querying NVD for {len(cpes_to_query)} CPEs...")

            for port, cpe in cpes_to_query:
                task = query_nvd_async(session, cpe, semaphore)
                tasks.append((port, cpe, task))

            # 3. Run all tasks
            results = await asyncio.gather(*[t[2] for t in tasks])

            # 4. Process results
            for i, result in enumerate(results):
                port = tasks[i][0]
                cpe = tasks[i][1]

                # result is guaranteed to be list (may be empty)
                cache[cpe] = result or []
                all_vulns[port] = result or []

        # Save updated cache
        save_cache_sync(cache)
        return all_vulns

def fetch_cves(cpe_results):
    """
    Allows synchronous nvm.py to call async logic.
    Includes a Windows-specific fix for the event loop.
    """
    if os.name == 'nt':
        try:
            asyncio.set_event_loop_policy(asyncio.WindowsSelectorEventLoopPolicy())
        except Exception:
            pass

    return asyncio.run(fetch_cves_async(cpe_results))


# --- TEST BLOCK ---
if __name__ == "__main__":
    mock_data = {80: {"cpe": "cpe:2.3:a:apache:http_server:2.4.49:*:*:*:*:*:*:*"}}
    print(json.dumps(fetch_cves(mock_data), indent=2))
