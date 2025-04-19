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

def main():
    domain = input("Enter domain to scan: ").strip()

    scanner = Scanner(domain)

    scanner.register_module(HTTPHeadersModule())
    scanner.register_module(SSLTLSModule())
    scanner.register_module(CookieSecurityModule())
    scanner.register_module(PortScanningModule())
    scanner.register_module(WebCrawlerModule())
    scanner.register_module(DirectoryBruteforceModule())
    scanner.register_module(XSSScannerModule())
    scanner.register_module(SQLInjectionScannerModule())  
    scanner.register_module(OpenRedirectScannerModule())

    scanner.run()

if __name__ == "__main__":
    main()
