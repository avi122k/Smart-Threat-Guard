import re
from urllib.parse import urlparse


def analyze_url(url):
    """
    Performs additional rule-based security checks on a URL.
    These checks are separate from the ML model.
    """

    # Add scheme if missing so urlparse works properly
    # Check whether the URL explicitly contains a scheme
    has_scheme = url.lower().startswith(("http://", "https://"))

    check_url = url

    if not has_scheme:
     check_url = "http://" + url
    parsed = urlparse(check_url)

    checks = []
    warnings = []

    # 1. HTTPS check
    # 1. HTTPS check
    if not has_scheme:
     checks.append({
        "check": "HTTPS Encryption",
        "status": "INFO",
        "message": "Protocol was not specified in the URL."
    })

    elif parsed.scheme == "https":
     checks.append({
        "check": "HTTPS Encryption",
        "status": "PASS",
        "message": "The URL uses HTTPS."
    })

    else:
     checks.append({
        "check": "HTTPS Encryption",
        "status": "WARNING",
        "message": "The URL uses HTTP instead of HTTPS."
    })
    warnings.append("URL uses HTTP instead of HTTPS")
    # 2. IP address check
    hostname = parsed.hostname or ""

    ip_pattern = r"^(?:\d{1,3}\.){3}\d{1,3}$"

    if re.match(ip_pattern, hostname):
        checks.append({
            "check": "IP Address Usage",
            "status": "WARNING",
            "message": "The URL uses an IP address instead of a domain name."
        })
        warnings.append("IP address used instead of domain name")
    else:
        checks.append({
            "check": "IP Address Usage",
            "status": "PASS",
            "message": "The URL uses a domain name."
        })

    # 3. Suspicious TLD check
    suspicious_tlds = [
        ".tk", ".ml", ".ga", ".cf", ".gq",
        ".top", ".xyz", ".click", ".download"
    ]

    if any(hostname.lower().endswith(tld) for tld in suspicious_tlds):
        checks.append({
            "check": "Domain Extension",
            "status": "WARNING",
            "message": "The domain uses a potentially suspicious TLD."
        })
        warnings.append("Potentially suspicious domain extension")
    else:
        checks.append({
            "check": "Domain Extension",
            "status": "PASS",
            "message": "No commonly flagged TLD detected."
        })

    # 4. URL shortener check
    shorteners = [
        "bit.ly",
        "tinyurl.com",
        "t.co",
        "goo.gl",
        "ow.ly",
        "is.gd",
        "buff.ly"
    ]

    if hostname.lower() in shorteners:
        checks.append({
            "check": "URL Shortener",
            "status": "WARNING",
            "message": "The URL uses a URL shortening service."
        })
        warnings.append("URL shortening service detected")
    else:
        checks.append({
            "check": "URL Shortener",
            "status": "PASS",
            "message": "No common URL shortener detected."
        })

    # 5. @ symbol check
    if "@" in url:
        checks.append({
            "check": "@ Symbol",
            "status": "WARNING",
            "message": "The URL contains an @ symbol."
        })
        warnings.append("@ symbol detected in URL")
    else:
        checks.append({
            "check": "@ Symbol",
            "status": "PASS",
            "message": "No @ symbol detected."
        })

    # 6. Suspicious keywords
    suspicious_keywords = [
        "login",
        "verify",
        "secure",
        "account",
        "update",
        "password",
        "bank",
        "confirm",
        "free",
        "gift"
    ]

    found_keywords = [
        keyword for keyword in suspicious_keywords
        if keyword in url.lower()
    ]

    if found_keywords:
        checks.append({
            "check": "Suspicious Keywords",
            "status": "WARNING",
            "message": "Suspicious keywords detected: " +
                       ", ".join(found_keywords)
        })
        warnings.append(
            "Suspicious keywords: " + ", ".join(found_keywords)
        )
    else:
        checks.append({
            "check": "Suspicious Keywords",
            "status": "PASS",
            "message": "No suspicious keywords detected."
        })

    # 7. Excessive subdomains
    subdomain_count = max(0, len(hostname.split(".")) - 2)

    if subdomain_count > 2:
        checks.append({
            "check": "Subdomain Count",
            "status": "WARNING",
            "message": f"Multiple subdomains detected ({subdomain_count})."
        })
        warnings.append(
            f"Excessive subdomains detected ({subdomain_count})"
        )
    else:
        checks.append({
            "check": "Subdomain Count",
            "status": "PASS",
            "message": "Subdomain count is within the normal range."
        })

    # 8. Unusually long URL
    if len(url) > 100:
        checks.append({
            "check": "URL Length",
            "status": "WARNING",
            "message": f"The URL is unusually long ({len(url)} characters)."
        })
        warnings.append("Unusually long URL")
    else:
        checks.append({
            "check": "URL Length",
            "status": "PASS",
            "message": "URL length is within the normal range."
        })

    return {
        "checks": checks,
        "warnings": warnings,
        "warning_count": len(warnings)
    }