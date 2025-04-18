from scanner.core import Scanner
from scanner.modules.headers import HTTPHeadersModule
from scanner.modules.ssl_tls import SSLTLSModule
from scanner.modules.cookies import CookieSecurityModule
from scanner.modules.open_ports import PortScanningModule
from scanner.modules.crawler import WebCrawlerModule

def main():
    domain = input("Enter domain to scan: ").strip()

    scanner = Scanner(domain)

    scanner.register_module(HTTPHeadersModule())
    scanner.register_module(SSLTLSModule())
    scanner.register_module(CookieSecurityModule())
    scanner.register_module(PortScanningModule())
    scanner.register_module(WebCrawlerModule())

    # Run the scan
    scanner.run()

if __name__ == "__main__":
    main()
