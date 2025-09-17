# phishing_features_parallel_ssl.py

import pandas as pd
import re
import tldextract
from urllib.parse import urlparse
import os
import ssl
import socket
from concurrent.futures import ThreadPoolExecutor, as_completed
import time

class FeatureExtractor:
    def __init__(self, url):
        self.url = url if url.startswith(("http://", "https://")) else "http://" + url
        self.parsed = urlparse(self.url)
        self.extracted = tldextract.extract(self.url)
        self.hostname = self.parsed.hostname or self.extracted.registered_domain
        self.domain = self.extracted.registered_domain or self.hostname

    # URL-based features
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
        return 1 if "https" in (self.extracted.subdomain or "").lower() or "https" in (self.extracted.domain or "").lower() else 0

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
        features = {
            "url": self.url,
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
            "ssl_certificate": self.check_ssl_certificate()  # now runs per URL
        }
        return features

# ------------------------
# Function for parallel processing
# ------------------------
def process_row(row, include_label):
    url = str(row["url"]).strip() if pd.notna(row["url"]) else "invalid_url"
    fe = FeatureExtractor(url)
    features = fe.get_features()
    if include_label:
        label = int(row["label"]) if pd.notna(row["label"]) else -1
        features["label"] = label
    return features

# ------------------------
# Main
# ------------------------
if __name__ == "__main__":
    input_csv = r"C:\Users\kinja\Downloads\Python_hackathon\raw_data.csv"
    output_csv = r"C:\Users\kinja\Downloads\Python_hackathon\training_data.csv"

    if not os.path.exists(input_csv):
        raise SystemExit("Input CSV not found.")

    df = pd.read_csv(input_csv)
    df.columns = df.columns.str.strip()

    include_label = "label" in df.columns

    if "url" not in df.columns:
        raise SystemExit("CSV must contain 'url' column.")

    feature_rows = []

    # Use ThreadPoolExecutor for parallel SSL checks
    max_workers = 10  # adjust based on CPU & network
    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        futures = [executor.submit(process_row, row, include_label) for _, row in df.iterrows()]
        for future in as_completed(futures):
            try:
                result = future.result()
                if result:
                    feature_rows.append(result)
            except Exception as e:
                print("Error processing a row:", e)

    out_df = pd.DataFrame(feature_rows)
    out_df.to_csv(output_csv, index=False)
    print(f"Features saved to {output_csv}")
