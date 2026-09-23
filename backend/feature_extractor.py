import re
from urllib.parse import urlparse


def extract_features(url):

    # Break the URL into different parts
    parsed = urlparse(url)

    hostname = parsed.netloc
    path = parsed.path
    query = parsed.query

    features = []

    # 1. URL length
    url_length = len(url)
    features.append(url_length)

    # 2. Number of dots
    dot_count = url.count(".")
    features.append(dot_count)

    # 3. Number of hyphens
    hyphen_count = url.count("-")
    features.append(hyphen_count)

    # 4. Number of underscores
    underscore_count = url.count("_")
    features.append(underscore_count)

    # 5. Number of @ symbols
    at_count = url.count("@")
    features.append(at_count)

    # 6. Number of digits
    digit_count = sum(c.isdigit() for c in url)
    features.append(digit_count)

    # 7. Number of special characters
    special_count = len(
        re.findall(r"[^a-zA-Z0-9]", url)
    )
    features.append(special_count)

    # 8. Number of subdomains
    subdomain_count = max(
        0,
        hostname.count(".") - 1
    )
    features.append(subdomain_count)

    # 9. Path length
    path_length = len(path)
    features.append(path_length)

    # 10. Query length
    query_length = len(query)
    features.append(query_length)

    # 11. Check whether URL uses an IP address
    ip_pattern = r"^(?:\d{1,3}\.){3}\d{1,3}$"

    if re.match(ip_pattern, hostname):
        ip_usage = 1
    else:
        ip_usage = 0

    features.append(ip_usage)

    # 12. Suspicious keywords
    suspicious_words = [
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

    suspicious_count = 0

    for word in suspicious_words:

        if word in url.lower():
            suspicious_count += 1

    features.append(suspicious_count)

    return features