"""
Phishing Email Analyzer - core analysis logic
Parses a raw .eml file / raw email text and flags phishing indicators.
"""
import re
import email
from email import policy
from email.parser import BytesParser, Parser
from urllib.parse import urlparse


LINK_TEXT_URL_RE = re.compile(r'<a[^>]+href=["\'](.*?)["\'][^>]*>(.*?)</a>', re.IGNORECASE | re.DOTALL)
URL_RE = re.compile(r'https?://[^\s"\'<>\)]+', re.IGNORECASE)

SUSPICIOUS_TLDS = {"ru", "tk", "ml", "ga", "cf", "gq", "xyz", "top", "click", "work", "support"}

URGENCY_WORDS = [
    "verify your account", "urgent", "suspended", "act now", "click immediately",
    "confirm your identity", "unusual activity", "limited time", "your account will be closed",
    "password expires", "unauthorized access", "click here to avoid", "final notice",
]


def parse_email(raw_bytes_or_str):
    """Parse raw email content (bytes or str) into an email.message.Message object."""
    if isinstance(raw_bytes_or_str, bytes):
        return BytesParser(policy=policy.default).parsebytes(raw_bytes_or_str)
    return Parser(policy=policy.default).parsestr(raw_bytes_or_str)


def get_body_text(msg):
    """Extract plain text + html body from the email."""
    text_parts = []
    html_parts = []
    if msg.is_multipart():
        for part in msg.walk():
            ctype = part.get_content_type()
            disp = str(part.get("Content-Disposition") or "")
            if "attachment" in disp:
                continue
            try:
                content = part.get_content()
            except Exception:
                continue
            if ctype == "text/plain":
                text_parts.append(content)
            elif ctype == "text/html":
                html_parts.append(content)
    else:
        try:
            content = msg.get_content()
        except Exception:
            content = ""
        if msg.get_content_type() == "text/html":
            html_parts.append(content)
        else:
            text_parts.append(content)
    return "\n".join(text_parts), "\n".join(html_parts)


def extract_domain(address):
    if not address:
        return ""
    match = re.search(r'@([\w\.-]+)', address)
    return match.group(1).lower() if match else ""


def analyze_headers(msg):
    findings = []
    score = 0

    from_header = msg.get("From", "")
    reply_to = msg.get("Reply-To", "")
    return_path = msg.get("Return-Path", "")

    from_domain = extract_domain(from_header)
    reply_domain = extract_domain(reply_to)
    return_domain = extract_domain(return_path)

    # Display name vs actual domain mismatch
    display_match = re.match(r'^\s*"?([^"<]*)"?\s*<(.+)>\s*$', from_header)
    if display_match:
        display_name = display_match.group(1).strip()
        actual_addr = display_match.group(2).strip()
        actual_domain = extract_domain(actual_addr)
        known_brands = ["paypal", "microsoft", "google", "apple", "amazon", "bank", "netflix", "irs", "chase"]
        for brand in known_brands:
            if brand in display_name.lower() and brand not in actual_domain.lower():
                findings.append({
                    "level": "high",
                    "text": f'Display name says "{display_name}" but the real sending address is {actual_addr} — classic spoofing.'
                })
                score += 30
                break

    # Reply-To mismatch
    if reply_domain and from_domain and reply_domain != from_domain:
        findings.append({
            "level": "medium",
            "text": f'Reply-To domain ({reply_domain}) does not match From domain ({from_domain}). Replies get redirected elsewhere.'
        })
        score += 15

    # Return-Path mismatch
    if return_domain and from_domain and return_domain != from_domain:
        findings.append({
            "level": "low",
            "text": f'Return-Path domain ({return_domain}) differs from From domain ({from_domain}).'
        })
        score += 5

    # Authentication-Results (SPF / DKIM / DMARC)
    auth_results = msg.get("Authentication-Results", "")
    if auth_results:
        for mech in ["spf", "dkim", "dmarc"]:
            m = re.search(rf'{mech}=(\w+)', auth_results, re.IGNORECASE)
            if m:
                result = m.group(1).lower()
                if result in ("fail", "softfail", "none"):
                    findings.append({
                        "level": "high" if result == "fail" else "medium",
                        "text": f'{mech.upper()} check result: {result.upper()} — sender authenticity could not be verified.'
                    })
                    score += 20 if result == "fail" else 10
                else:
                    findings.append({
                        "level": "info",
                        "text": f'{mech.upper()} check passed ({result}).'
                    })
    else:
        findings.append({
            "level": "medium",
            "text": "No Authentication-Results header found — cannot verify SPF/DKIM/DMARC from this copy of the email."
        })
        score += 5

    return findings, score, from_domain


def analyze_links(html_body, text_body):
    findings = []
    score = 0
    seen_urls = set()

    # Anchor tags: check text-vs-href mismatch
    for href, link_text in LINK_TEXT_URL_RE.findall(html_body or ""):
        href_clean = href.strip()
        seen_urls.add(href_clean)
        visible_urls = URL_RE.findall(link_text)
        for visible in visible_urls:
            if urlparse(visible).netloc and urlparse(visible).netloc != urlparse(href_clean).netloc:
                findings.append({
                    "level": "high",
                    "text": f'Link text shows "{visible}" but actually points to {href_clean} — mismatched link.'
                })
                score += 25

    # All raw URLs found in text + html
    all_text = f"{text_body}\n{html_body}"
    for url in set(URL_RE.findall(all_text)):
        seen_urls.add(url)

    domain_findings_added = set()
    for url in seen_urls:
        domain = urlparse(url).netloc.lower()
        if not domain or domain in domain_findings_added:
            continue
        domain_findings_added.add(domain)
        tld = domain.split(".")[-1]
        if tld in SUSPICIOUS_TLDS:
            findings.append({
                "level": "medium",
                "text": f'Link uses a commonly-abused top-level domain: {domain} (.{tld})'
            })
            score += 15
        if re.search(r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}', domain):
            findings.append({
                "level": "high",
                "text": f'Link points directly to a raw IP address ({domain}) instead of a domain name — highly suspicious.'
            })
            score += 25
        if domain.count("-") >= 3 or domain.count(".") >= 4:
            findings.append({
                "level": "medium",
                "text": f'Link domain looks unusually long/complex, a common look-alike trick: {domain}'
            })
            score += 10

    return findings, score, list(seen_urls)


def analyze_content(text_body, html_body):
    findings = []
    score = 0
    combined = f"{text_body}\n{html_body}".lower()
    hits = [w for w in URGENCY_WORDS if w in combined]
    for w in hits:
        findings.append({
            "level": "low",
            "text": f'Uses urgency/pressure language: "{w}"'
        })
        score += 5
    return findings, score


def verdict_from_score(score):
    if score >= 50:
        return "Likely Phishing", "danger"
    elif score >= 20:
        return "Suspicious", "warning"
    else:
        return "Likely Safe", "safe"


def analyze_email(raw_content):
    """Main entry point. raw_content: bytes or str of the raw email (.eml)."""
    msg = parse_email(raw_content)
    text_body, html_body = get_body_text(msg)

    header_findings, header_score, from_domain = analyze_headers(msg)
    link_findings, link_score, urls = analyze_links(html_body, text_body)
    content_findings, content_score = analyze_content(text_body, html_body)

    total_score = header_score + link_score + content_score
    verdict, verdict_class = verdict_from_score(total_score)

    return {
        "subject": msg.get("Subject", "(no subject)"),
        "from": msg.get("From", "(unknown)"),
        "to": msg.get("To", "(unknown)"),
        "date": msg.get("Date", "(unknown)"),
        "from_domain": from_domain,
        "score": total_score,
        "verdict": verdict,
        "verdict_class": verdict_class,
        "header_findings": header_findings,
        "link_findings": link_findings,
        "content_findings": content_findings,
        "urls_found": urls,
        "all_findings": header_findings + link_findings + content_findings,
    }
