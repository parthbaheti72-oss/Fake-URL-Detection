import requests
import os
import base64
from dotenv import load_dotenv

load_dotenv()

VT_API_KEY = os.getenv("VIRUSTOTAL_API_KEY")


# ─────────────────────────────────────────
# VIRUSTOTAL
# ─────────────────────────────────────────

def check_virustotal(url):
    """
    Returns:
      {
        "flagged": bool,
        "malicious": int,
        "suspicious": int,
        "harmless": int,
        "total_engines": int,
        "scan_id": str,
        "error": str|None
      }
    """
    if not VT_API_KEY:
        return {
            "flagged": False, "malicious": 0, "suspicious": 0,
            "harmless": 0, "total_engines": 0, "scan_id": None, "error": "API key not set"
        }

    headers = {"x-apikey": VT_API_KEY}

    try:
        # Step 1: Submit URL for scanning
        submit_res = requests.post(
            "https://www.virustotal.com/api/v3/urls",
            headers=headers,
            data={"url": url},
            timeout=8
        )
        submit_data = submit_res.json()
        scan_id = submit_data.get("data", {}).get("id", "")

        if not scan_id:
            return {
                "flagged": False, "malicious": 0, "suspicious": 0,
                "harmless": 0, "total_engines": 0, "scan_id": None,
                "error": "Could not get scan ID"
            }

        # Step 2: Get analysis results
        url_id = base64.urlsafe_b64encode(url.encode()).decode().rstrip("=")
        analysis_res = requests.get(
            f"https://www.virustotal.com/api/v3/urls/{url_id}",
            headers=headers,
            timeout=8
        )
        analysis_data = analysis_res.json()
        stats = analysis_data.get("data", {}).get("attributes", {}).get("last_analysis_stats", {})

        malicious  = stats.get("malicious", 0)
        suspicious = stats.get("suspicious", 0)
        harmless   = stats.get("harmless", 0)
        undetected = stats.get("undetected", 0)
        total      = malicious + suspicious + harmless + undetected

        return {
            "flagged": malicious > 0 or suspicious > 2,
            "malicious": malicious,
            "suspicious": suspicious,
            "harmless": harmless,
            "total_engines": total,
            "scan_id": url_id,
            "error": None
        }

    except requests.exceptions.Timeout:
        return {
            "flagged": False, "malicious": 0, "suspicious": 0,
            "harmless": 0, "total_engines": 0, "scan_id": None, "error": "Timeout"
        }
    except Exception as e:
        return {
            "flagged": False, "malicious": 0, "suspicious": 0,
            "harmless": 0, "total_engines": 0, "scan_id": None, "error": str(e)
        }
