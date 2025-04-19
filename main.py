# main.py

import argparse
from scanner.core import Scanner
from scanner.modules.headers import HTTPHeadersModule
from scanner.modules.ssl_tls import SSLTLSModule
from scanner.modules.cookies import CookieSecurityModule
from scanner.modules.open_ports import PortScanningModule
from scanner.modules.crawler import WebCrawlerModule
from scanner.modules.dir_bruteforce import DirectoryBruteforceModule
from scanner.modules.xss_scanner import XSSScannerModule
from scanner.modules.sql_injection_scanner import SQLInjectionScannerModule
from scanner.modules.open_redirect_scanner import OpenRedirectScannerModule
from scanner.modules.csrf_scanner import CSRFScannerModule

def main():
    parser = argparse.ArgumentParser(description="Website Security Scanner")
    parser.add_argument("domain", help="Target domain to scan (e.g., example.com)")
    parser.add_argument("--full-scan", action="store_true", help="Scan all 65535 ports instead of top 100")
    parser.add_argument("--stealth", action="store_true", help="Slow down port scan to avoid detection")

    args = parser.parse_args()

    scanner = Scanner(args.domain)

    scanner.register_module(HTTPHeadersModule())
    scanner.register_module(SSLTLSModule())
    scanner.register_module(CookieSecurityModule())
    scanner.register_module(PortScanningModule(full_scan=args.full_scan, stealth=args.stealth))
    scanner.register_module(WebCrawlerModule())
    scanner.register_module(DirectoryBruteforceModule())
    scanner.register_module(XSSScannerModule())
    scanner.register_module(SQLInjectionScannerModule())
    scanner.register_module(OpenRedirectScannerModule())
    scanner.register_module(CSRFScannerModule())

    scanner.run()

if __name__ == "__main__":
    main()
