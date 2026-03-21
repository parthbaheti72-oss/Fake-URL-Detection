from flask import Flask, request, jsonify, send_file
from flask_cors import CORS
from detector import analyze_url
from api_checks import check_virustotal
import datetime
import csv
import io

app = Flask(__name__)
CORS(app)

history = []


def combined_score(heuristic_result, vt_result):
    """
    Scoring weights:
      Heuristic Engine:  60%  (our own detection — typosquatting, leet speak, keywords, etc.)
      VirusTotal:        40%  (crowd-sourced 70+ antivirus engines)

    If VirusTotal has no data (API error / not in database),
    heuristics get 90% weight so new phishing URLs aren't missed.
    """
    h_score = heuristic_result["score"]

    vt_score = 0
    if vt_result.get("total_engines", 0) > 0:
        ratio = vt_result["malicious"] / vt_result["total_engines"]
        if ratio > 0.1:
            vt_score = 100
        elif ratio > 0.05 or vt_result["suspicious"] > 3:
            vt_score = 60
        elif vt_result["malicious"] > 0:
            vt_score = 30

    # Check if VT actually returned useful data
    vt_has_data = not vt_result.get("error") and vt_result.get("total_engines", 0) > 0

    if vt_has_data:
        # VT has data — use balanced weights
        final = (h_score * 0.60) + (vt_score * 0.40)
    else:
        # VT has NO data — trust heuristics heavily
        final = h_score * 0.90

    final = min(round(final), 100)

    # Hard override: if VT explicitly flags it, ensure high score
    if vt_result.get("malicious", 0) > 2:
        final = max(final, 75)

    if final <= 20:   verdict = "SAFE"
    elif final <= 50: verdict = "SUSPICIOUS"
    else:             verdict = "FAKE / MALICIOUS"

    return final, verdict


def analyze_single_url(url):
    """Run full analysis pipeline on one URL."""
    if not url.startswith("http"):
        url = "https://" + url

    heuristic = analyze_url(url)
    vt        = check_virustotal(url)

    final_score, verdict = combined_score(heuristic, vt)

    return {
        "url": url,
        "domain": heuristic["domain"],
        "timestamp": datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "score": final_score,
        "verdict": verdict,
        "heuristic_score": heuristic["score"],
        "flags": heuristic["flags"],
        "flags_triggered": heuristic["flags_triggered"],
        "typo_matches": heuristic["typo_matches"],
        "brand_subdomain": heuristic["brand_subdomain"],
        "vt": {
            "flagged": vt["flagged"],
            "malicious": vt["malicious"],
            "suspicious": vt["suspicious"],
            "harmless": vt["harmless"],
            "total_engines": vt["total_engines"],
            "scan_id": vt["scan_id"],
            "error": vt["error"]
        }
    }


# ═══════════════════════════════════════════════
#  CORE ROUTES
# ═══════════════════════════════════════════════

@app.route("/")
def home():
    return jsonify({"message": "URLGuard v2 API — Heuristics + VirusTotal + Bulk Scanner"})


@app.route("/analyze", methods=["POST"])
def analyze():
    data = request.get_json()
    url = data.get("url", "").strip()
    if not url:
        return jsonify({"error": "No URL provided"}), 400

    result = analyze_single_url(url)

    history.insert(0, result)
    if len(history) > 10:
        history.pop()

    return jsonify(result)


@app.route("/history", methods=["GET"])
def get_history():
    return jsonify(history)


@app.route("/brands", methods=["GET"])
def get_brands():
    from detector import KNOWN_BRANDS
    return jsonify(list(KNOWN_BRANDS.values()))


# ═══════════════════════════════════════════════
#  BULK CSV URL SCANNER
# ═══════════════════════════════════════════════

@app.route("/bulk-scan", methods=["POST"])
def bulk_scan():
    """
    Accepts:
      A) CSV file upload  (form field: 'file')
      B) JSON body        {"urls": ["url1", "url2", ...]}
    Scans up to 50 URLs, returns results + summary.
    """
    urls = []

    if "file" in request.files:
        file = request.files["file"]
        if file.filename == "":
            return jsonify({"error": "Empty file"}), 400
        try:
            stream = io.StringIO(file.stream.read().decode("utf-8"))
            reader = csv.reader(stream)
            for row in reader:
                for cell in row:
                    cell = cell.strip().strip('"').strip("'")
                    if cell and cell.lower() not in ("url", "urls", "link", "links", "website"):
                        if "." in cell and len(cell) > 4:
                            urls.append(cell)
        except Exception as e:
            return jsonify({"error": f"Failed to parse CSV: {str(e)}"}), 400
    else:
        data = request.get_json(silent=True)
        if data and "urls" in data:
            urls = [u.strip() for u in data["urls"] if u.strip()]
        else:
            return jsonify({"error": "No file or URL list provided"}), 400

    if len(urls) == 0:
        return jsonify({"error": "No valid URLs found in input"}), 400
    if len(urls) > 50:
        urls = urls[:50]

    # Deduplicate
    seen = set()
    unique = []
    for u in urls:
        key = u.lower()
        if key not in seen:
            seen.add(key)
            unique.append(u)
    urls = unique

    results = []
    summary = {"total": len(urls), "safe": 0, "suspicious": 0, "malicious": 0}

    for url in urls:
        try:
            result = analyze_single_url(url)
            results.append(result)
            v = result["verdict"]
            if v == "SAFE":
                summary["safe"] += 1
            elif v == "SUSPICIOUS":
                summary["suspicious"] += 1
            else:
                summary["malicious"] += 1
        except Exception as e:
            results.append({
                "url": url, "domain": "", "score": -1,
                "verdict": "ERROR", "flags": [str(e)],
                "flags_triggered": 0, "heuristic_score": 0,
                "typo_matches": [], "brand_subdomain": None,
                "vt": {"flagged": False, "malicious": 0, "suspicious": 0,
                       "harmless": 0, "total_engines": 0, "scan_id": None, "error": str(e)}
            })

    return jsonify({
        "summary": summary,
        "results": results,
        "scanned_at": datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    })


@app.route("/bulk-scan/export-csv", methods=["POST"])
def bulk_export_csv():
    """Same as /bulk-scan but returns a downloadable CSV file."""
    data = request.get_json(silent=True)
    urls = []
    if data and "urls" in data:
        urls = [u.strip() for u in data["urls"] if u.strip()]
    if not urls:
        return jsonify({"error": "No URLs provided"}), 400
    urls = urls[:50]

    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerow(["URL", "Domain", "Risk Score", "Verdict",
                     "Heuristic Score", "Flags Triggered", "Flags",
                     "VT Malicious", "VT Suspicious", "Scanned At"])

    for url in urls:
        try:
            r = analyze_single_url(url)
            writer.writerow([
                r["url"], r["domain"], r["score"], r["verdict"],
                r["heuristic_score"], r["flags_triggered"],
                " | ".join(r["flags"]),
                r["vt"]["malicious"], r["vt"]["suspicious"],
                r["timestamp"]
            ])
        except Exception as e:
            writer.writerow([url, "", -1, "ERROR", "", "", str(e), "", "", ""])

    output.seek(0)
    mem = io.BytesIO(output.getvalue().encode("utf-8"))
    return send_file(mem, mimetype="text/csv", as_attachment=True,
                     download_name=f"urlguard_report_{datetime.datetime.now().strftime('%Y%m%d_%H%M%S')}.csv")


if __name__ == "__main__":
    app.run(debug=True, port=5000)
