#!/usr/bin/env python3
import requests
import re
import ssl
import socket
import json
from datetime import datetime
from urllib.parse import urlparse

LOG_FILE = "scan_logs.json"

def check_https(url):
    try:
        parsed = urlparse(url)
        hostname = parsed.hostname
        context = ssl.create_default_context()
        with socket.create_connection((hostname, 443), timeout=5) as sock:
            with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                cert = ssock.getpeercert()
                return True, cert
    except Exception:
        return False, None

def check_redirects(url):
    try:
        r = requests.get(url, allow_redirects=True, timeout=8)
        chain = [resp.url for resp in r.history] + [r.url]
        return chain
    except Exception:
        return ["Error retrieving redirect chain"]

def check_suspicious(url):
    alerts = []
    if "@" in url: alerts.append("Contains '@' (can hide real URL)")
    if url.count("//") > 1: alerts.append("Multiple '//' segments detected")
    if re.search(r"[0-9]{1,3}(\.[0-9]{1,3}){3}", url): alerts.append("Direct IP address detected")
    if any(x in url for x in ["xn--", "%"]): alerts.append("Possible punycode or encoded characters")
    return alerts

def save_report(data):
    try:
        logs = []
        try:
            with open(LOG_FILE, "r") as f:
                logs = json.load(f)
        except:
            pass

        logs.append(data)
        with open(LOG_FILE, "w") as f:
            json.dump(logs, f, indent=4)
    except:
        pass

def scan_url(url):
    result = {
        "url": url,
        "timestamp": str(datetime.now()),
        "redirect_chain": check_redirects(url),
        "suspicious_indicators": check_suspicious(url),
    }

    https_ok, cert = check_https(url)
    result["https_valid"] = https_ok
    result["certificate"] = cert

    save_report(result)
    return result

def print_report(result):
    print("\n=== URL SAFETY REPORT ===")
    print("URL:", result["url"])
    print("Time:", result["timestamp"])

    print("\n➡️ Redirect Chain:")
    for c in result["redirect_chain"]:
        print("  →", c)

    print("\n⚠️ Suspicious Indicators:")
    if result["suspicious_indicators"]:
        for a in result["suspicious_indicators"]:
            print(" -", a)
    else:
        print("None found.")

    print("\n🔐 HTTPS Certificate:")
    if result["https_valid"]:
        print("Valid certificate.")
        print("Issuer:", result["certificate"].get("issuer"))
        print("Valid:", result["certificate"].get("notBefore"), "to", result["certificate"].get("notAfter"))
    else:
        print("Invalid or missing HTTPS certificate.")

def menu():
    while True:
        print("
=== URL SAFETY TOOL ===")
        print("[1] Scan URL")
        print("[2] View Logs")
        print("[3] Export Logs (JSON)")
        print("[4] Exit")

        choice = input("Select: ")

        if choice == "1":
            url = input("Enter URL: ")
            result = scan_url(url)
            print_report(result)

        elif choice == "2":
            try:
                with open(LOG_FILE, "r") as f:
                    logs = json.load(f)
                print("
=== Scan Logs ===")
                for i, entry in enumerate(logs, 1):
                    print(f"{i}. {entry['url']} - {entry['timestamp']}")
            except:
                print("No logs found.")

        elif choice == "3":
            print("Logs exported → scan_logs.json")

        elif choice == "4":
            print("Goodbye!")
            break

        else:
            print("Invalid choice.")

if __name__ == "__main__":
    menu()
