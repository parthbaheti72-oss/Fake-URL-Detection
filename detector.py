import re
import urllib.parse

# ═══════════════════════════════════════════════
#  KNOWN BRANDS — brand_keyword: legitimate_domain
# ═══════════════════════════════════════════════

KNOWN_BRANDS = {
    "google": "google.com",
    "gmail": "gmail.com",
    "youtube": "youtube.com",
    "facebook": "facebook.com",
    "instagram": "instagram.com",
    "twitter": "twitter.com",
    "whatsapp": "whatsapp.com",
    "amazon": "amazon.com",
    "apple": "apple.com",
    "icloud": "icloud.com",
    "microsoft": "microsoft.com",
    "outlook": "outlook.com",
    "linkedin": "linkedin.com",
    "netflix": "netflix.com",
    "paypal": "paypal.com",
    "ebay": "ebay.com",
    "flipkart": "flipkart.com",
    "paytm": "paytm.com",
    "hdfc": "hdfcbank.com",
    "sbi": "onlinesbi.com",
    "icici": "icicibank.com",
    "axis": "axisbank.com",
    "github": "github.com",
    "dropbox": "dropbox.com",
    "spotify": "spotify.com",
    "zoom": "zoom.us",
    "adobe": "adobe.com",
    "shopify": "shopify.com",
    "wordpress": "wordpress.com",
    "yahoo": "yahoo.com",
}

# Pairs that are legitimately similar — NOT typosquatting
SAFE_PAIRS = {
    ("paypal.com", "paytm.com"),
    ("paytm.com", "paypal.com"),
    ("spotify.com", "shopify.com"),
    ("shopify.com", "spotify.com"),
}

# Suspicious TLDs commonly used in phishing
SUSPICIOUS_TLDS = {".xyz", ".top", ".club", ".tk", ".ml", ".ga", ".cf", ".work", ".click", ".buzz", ".gq", ".icu"}

# Keywords in URL path/domain that indicate phishing
PHISHING_KEYWORDS = [
    "login", "signin", "sign-in", "verify", "secure", "update",
    "account", "banking", "confirm", "password", "credential",
    "alert", "suspended", "unlock", "recover", "support",
    "wallet", "netbanking", "auth", "offer", "free", "premium",
    "download", "security", "inbox"
]

LEET_MAP = {
    '0': 'o', '1': 'i', '3': 'e', '4': 'a',
    '5': 's', '6': 'g', '7': 't', '8': 'b', '@': 'a'
}


# ═══════════════════════════════════════════════
#  UTILITY FUNCTIONS
# ═══════════════════════════════════════════════

def normalize_leet(text):
    """Convert leet speak to normal text: g00gle → google"""
    result = ""
    for ch in text.lower():
        result += LEET_MAP.get(ch, ch)
    return result


def levenshtein(s1, s2):
    """Calculate edit distance between two strings"""
    if len(s1) < len(s2):
        return levenshtein(s2, s1)
    if len(s2) == 0:
        return len(s1)
    prev = range(len(s2) + 1)
    for i, c1 in enumerate(s1):
        curr = [i + 1]
        for j, c2 in enumerate(s2):
            ins = prev[j + 1] + 1
            dele = curr[j] + 1
            sub = prev[j] + (c1 != c2)
            curr.append(min(ins, dele, sub))
        prev = curr
    return prev[len(s2)]


def similarity_score(s1, s2):
    """Return similarity % between two strings (100 = identical)"""
    dist = levenshtein(s1, s2)
    max_len = max(len(s1), len(s2), 1)
    return round((1 - dist / max_len) * 100, 1)


def extract_domain(url):
    """Extract clean domain from URL"""
    if not url.startswith("http"):
        url = "https://" + url
    parsed = urllib.parse.urlparse(url)
    netloc = parsed.netloc.lower()
    if netloc.startswith("www."):
        netloc = netloc[4:]
    return netloc


def is_ip_address(domain):
    """Check if domain is an IP address"""
    return bool(re.match(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}', domain))


def get_tld(domain):
    """Extract TLD from domain"""
    parts = domain.split(".")
    if len(parts) >= 2:
        return "." + parts[-1]
    return ""


def get_base_domain(domain):
    """Get the main part of domain (without TLD): g00gle-secure.xyz → g00gle-secure"""
    parts = domain.split(".")
    if len(parts) >= 2:
        return ".".join(parts[:-1])  # everything except TLD
    return domain


def is_known_legit_domain(domain):
    """Check if domain exactly matches a known legitimate domain"""
    return domain in KNOWN_BRANDS.values()


# ═══════════════════════════════════════════════
#  BRAND DETECTION IN DOMAIN
# ═══════════════════════════════════════════════

def find_brand_in_text(text):
    """
    Check if any known brand name appears inside the text.
    Returns list of (brand, legit_domain) matches.
    """
    matches = []
    normalized = normalize_leet(text)

    for brand, legit_domain in KNOWN_BRANDS.items():
        # Direct brand match in original or leet-decoded text
        if brand in text.lower() or brand in normalized:
            matches.append((brand, legit_domain))

    return matches


def detect_typosquatting(domain):
    """
    Advanced typosquatting detection.
    Compares the domain base (without hyphens/extra parts) against brands.
    """
    results = []
    if is_known_legit_domain(domain):
        return results  # It's the real domain, not typosquatting

    # Get the full base (everything before TLD)
    base = get_base_domain(domain)  # e.g. "g00gle-secure" or "arnazon"
    normalized_full = normalize_leet(base)

    # Also try just the first segment before any hyphen
    segments = base.split("-")
    first_segment = segments[0]
    normalized_first = normalize_leet(first_segment)

    for brand, legit_domain in KNOWN_BRANDS.items():
        legit_base = legit_domain.split(".")[0]  # "google" from "google.com"

        # Skip safe pairs (paypal↔paytm etc.)
        if (domain, legit_domain) in SAFE_PAIRS:
            continue

        # === Check 1: First segment similarity (handles g00gle-secure → google) ===
        sim_first = max(
            similarity_score(first_segment, legit_base),
            similarity_score(normalized_first, legit_base)
        )

        # === Check 2: Full base similarity (handles arnazon → amazon) ===
        sim_full = max(
            similarity_score(base.replace("-", ""), legit_base),
            similarity_score(normalized_full.replace("-", ""), legit_base)
        )

        # === Check 3: Full domain similarity ===
        sim_domain = similarity_score(domain, legit_domain)

        best_sim = max(sim_first, sim_full, sim_domain)

        # Flag if similar enough but NOT the real thing
        if best_sim >= 70 and domain != legit_domain:
            # Determine attack type
            attack_type = "Typosquatting"
            leet_decoded = None

            if normalized_first != first_segment and normalized_first == legit_base:
                attack_type = "Leet Speak Attack"
                leet_decoded = normalize_leet(domain)
            elif normalized_full.replace("-", "") != base.replace("-", "") and normalized_full.replace("-", "") == legit_base:
                attack_type = "Leet Speak Attack"
                leet_decoded = normalize_leet(domain)
            elif levenshtein(first_segment, legit_base) == 1 or levenshtein(base.replace("-", ""), legit_base) == 1:
                attack_type = "Character Substitution"
            elif abs(len(first_segment) - len(legit_base)) == 1:
                attack_type = "Character Addition/Deletion"

            results.append({
                "brand": brand.capitalize(),
                "legit_domain": legit_domain,
                "similarity": best_sim,
                "attack_type": attack_type,
                "leet_normalized": leet_decoded
            })

    results.sort(key=lambda x: x["similarity"], reverse=True)
    return results[:3]


def check_brand_in_subdomain(domain):
    """Detect brand names stuffed into subdomains: paypal.evil.com"""
    parts = domain.split(".")
    if len(parts) <= 2:
        return None
    subdomain_parts = parts[:-2]
    for brand in KNOWN_BRANDS:
        for part in subdomain_parts:
            if brand in part.lower():
                legit = KNOWN_BRANDS[brand]
                return {
                    "brand": brand.capitalize(),
                    "legit_domain": legit,
                    "attack_type": "Brand in Subdomain",
                    "example": f"{brand}.{'.'.join(parts[-2:])}"
                }
    return None


def check_brand_in_domain_parts(domain):
    """
    Detect brand names embedded in hyphenated domains:
    e.g. netflix-account-verify.ml, secure-sbi-netbanking.tk
    This catches cases where the full domain isn't similar enough
    for typosquatting detection, but the brand is clearly being used.
    """
    if is_known_legit_domain(domain):
        return None

    base = get_base_domain(domain)
    parts = base.split("-")
    normalized_parts = [normalize_leet(p) for p in parts]
    all_parts = parts + normalized_parts

    for brand, legit_domain in KNOWN_BRANDS.items():
        for part in all_parts:
            # Exact brand match in a segment
            if part == brand:
                return {
                    "brand": brand.capitalize(),
                    "legit_domain": legit_domain,
                    "attack_type": "Brand Name in Domain",
                    "detail": f"'{brand}' found in domain segments"
                }
            # Brand contained in a segment (e.g. "netbanking" doesn't match but "sbi" does)
            if len(brand) >= 3 and brand in part and part != brand:
                return {
                    "brand": brand.capitalize(),
                    "legit_domain": legit_domain,
                    "attack_type": "Brand Name in Domain",
                    "detail": f"'{brand}' found inside '{part}'"
                }
    return None


# ═══════════════════════════════════════════════
#  MAIN ANALYSIS FUNCTION
# ═══════════════════════════════════════════════

def analyze_url(url):
    domain = extract_domain(url)
    if not url.startswith("http"):
        url = "https://" + url

    parsed = urllib.parse.urlparse(url)
    full_url = url.lower()
    path = parsed.path.lower()

    flags = []
    score = 0

    # ── If it's a known legit domain, return immediately ──
    if is_known_legit_domain(domain):
        return {
            "score": 0,
            "verdict": "SAFE",
            "flags": [],
            "domain": domain,
            "typo_matches": [],
            "brand_subdomain": None,
            "flags_triggered": 0,
        }

    # ── Run all detection checks ──
    typo_matches = detect_typosquatting(domain)
    brand_subdomain = check_brand_in_subdomain(domain)
    brand_in_domain = check_brand_in_domain_parts(domain)
    tld = get_tld(domain)
    is_ip = is_ip_address(domain)
    base = get_base_domain(domain)

    # ═══ 1. TYPOSQUATTING (high threat) ═══
    if typo_matches:
        top = typo_matches[0]
        sim = top["similarity"]
        if sim >= 90:
            score += 50
        elif sim >= 80:
            score += 40
        else:
            score += 25
        flags.append(f"{top['attack_type']}: Looks like '{top['legit_domain']}' ({sim}% similar)")
        if top.get("leet_normalized"):
            flags.append(f"Leet speak decoded: '{domain}' → '{top['leet_normalized']}'")

    # ═══ 2. BRAND IN SUBDOMAIN (high threat) ═══
    if brand_subdomain:
        score += 40
        flags.append(f"Brand Impersonation: '{brand_subdomain['brand']}' name used in subdomain to fake legitimacy")

    # ═══ 3. BRAND NAME EMBEDDED IN DOMAIN (high threat) ═══
    if brand_in_domain and not typo_matches:
        # Only add if typosquatting didn't already catch it
        score += 35
        flags.append(f"Brand Name Detected: '{brand_in_domain['brand']}' found in domain — impersonating {brand_in_domain['legit_domain']}")

    # ═══ 4. SUSPICIOUS TLD ═══
    if tld in SUSPICIOUS_TLDS:
        score += 20
        flags.append(f"Suspicious TLD: '{tld}' is commonly used in fake/phishing domains")

    # ═══ 5. NO HTTPS ═══
    if not url.startswith("https"):
        score += 10
        flags.append("No HTTPS — connection is not encrypted")

    # ═══ 6. IP ADDRESS AS DOMAIN ═══
    if is_ip:
        score += 30
        flags.append("IP address used instead of domain name — highly suspicious")

    # ═══ 7. PHISHING KEYWORDS IN URL ═══
    keyword_hits = []
    for kw in PHISHING_KEYWORDS:
        if kw in base.lower() or kw in path:
            keyword_hits.append(kw)
    if keyword_hits:
        count = len(keyword_hits)
        if count >= 3:
            score += 25
        elif count >= 2:
            score += 15
        else:
            score += 10
        flags.append(f"Phishing keywords found: {', '.join(keyword_hits[:5])}")

    # ═══ 8. MULTIPLE HYPHENS ═══
    if base.count("-") >= 2:
        score += 10
        flags.append("Multiple hyphens in domain — common in fake sites")

    # ═══ 9. VERY LONG DOMAIN ═══
    if len(domain) > 30:
        score += 10
        flags.append(f"Domain is unusually long ({len(domain)} chars)")

    # ═══ 10. DIGITS IN DOMAIN ═══
    if re.search(r"\d", base):
        # Only flag if not already caught by leet speak detection
        already_leet = any(m.get("attack_type") == "Leet Speak Attack" for m in typo_matches)
        if not already_leet:
            score += 5
            flags.append("Digits in domain name — often used to mimic real brands")

    # ═══ 11. HEX ENCODING / @ SYMBOL ═══
    if "@" in url:
        score += 20
        flags.append("'@' symbol in URL — can redirect to a different host")

    if "%" in url and re.search(r'%[0-9a-fA-F]{2}', url):
        score += 10
        flags.append("Hex encoding detected — may be hiding the real URL")

    # ═══ 12. COMBO BOOST: suspicious TLD + brand reference = almost certainly fake ═══
    has_brand_ref = bool(typo_matches or brand_subdomain or brand_in_domain)
    if tld in SUSPICIOUS_TLDS and has_brand_ref:
        score += 15
        flags.append("Dangerous combo: Brand impersonation + suspicious TLD")

    # ═══ 13. COMBO BOOST: suspicious TLD + phishing keywords ═══
    if tld in SUSPICIOUS_TLDS and keyword_hits and not has_brand_ref:
        score += 10
        flags.append("Suspicious combo: Phishing keywords + suspicious TLD")

    # ── Cap at 100 ──
    score = min(score, 100)

    # ── Verdict ──
    if score <= 20:
        verdict = "SAFE"
    elif score <= 50:
        verdict = "SUSPICIOUS"
    else:
        verdict = "FAKE / MALICIOUS"

    return {
        "score": score,
        "verdict": verdict,
        "flags": flags,
        "domain": domain,
        "typo_matches": typo_matches,
        "brand_subdomain": brand_subdomain,
        "flags_triggered": len(flags),
    }
