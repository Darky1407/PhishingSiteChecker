# url_extractor.py
import re
import tldextract
from urllib.parse import urlparse
import ssl
import socket
import time

class FeatureExtractor:
    def __init__(self, url):
        self.url = url if url.startswith(("http://", "https://")) else "http://" + url
        self.parsed = urlparse(self.url)
        self.extracted = tldextract.extract(self.url)
        self.hostname = self.parsed.hostname or self.extracted.registered_domain
        self.domain = self.extracted.registered_domain or self.hostname

    # --- URL-based features ---
    def having_ip(self):
        return 1 if re.search(r'(\d{1,3}\.){3}\d{1,3}', self.url) else 0

    def url_length(self):
        return len(self.url)

    def shortening_service(self):
        return 1 if re.search(r"bit\.ly|goo\.gl|tinyurl|ow\.ly|t\.co", self.url, flags=re.IGNORECASE) else 0

    def having_at_symbol(self):
        return 1 if "@" in self.url else 0

    def double_slash_redirect(self):
        count = self.url.count("//")
        if self.parsed.scheme:
            count -= 1
        return 1 if count > 0 else 0

    def prefix_suffix(self):
        return 1 if "-" in (self.domain or "") else 0

    def having_sub_domain(self):
        if not self.extracted.subdomain:
            return 0
        parts = [p for p in self.extracted.subdomain.split(".") if p]
        return len(parts)

    def https_token(self):
        return 1 if "https" in (self.extracted.subdomain or "").lower() else 0

    def port(self):
        try:
            port = self.parsed.port
            return 1 if port and port not in [80, 443] else 0
        except:
            return 0

    def ssl_final_state(self):
        return 1 if self.parsed.scheme == "https" else 0

    def dns_record(self):
        try:
            if not self.hostname:
                return 0
            socket.gethostbyname(self.hostname)
            return 1
        except:
            return 0

    def check_ssl_certificate(self, timeout=3, retries=1):
        for attempt in range(retries + 1):
            try:
                hostname = self.hostname
                if not hostname:
                    return 0
                ctx = ssl.create_default_context()
                with socket.create_connection((hostname, 443), timeout=timeout) as sock:
                    with ctx.wrap_socket(sock, server_hostname=hostname) as ssock:
                        cert = ssock.getpeercert()
                        return 1 if cert else 0
            except Exception:
                time.sleep(0.05)
                continue
        return 0

    def get_features(self):
        return {
            "having_ip": self.having_ip(),
            "url_length": self.url_length(),
            "shortening_service": self.shortening_service(),
            "having_at_symbol": self.having_at_symbol(),
            "double_slash_redirect": self.double_slash_redirect(),
            "prefix_suffix": self.prefix_suffix(),
            "having_sub_domain": self.having_sub_domain(),
            "https_token": self.https_token(),
            "port": self.port(),
            "ssl_final_state": self.ssl_final_state(),
            "dns_record": self.dns_record(),
            "ssl_certificate": self.check_ssl_certificate()
        }
