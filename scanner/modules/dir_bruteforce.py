# scanner/modules/dir_bruteforce.py

from scanner.utils.http import fetch_url

class DirectoryBruteforceModule:
    def __init__(self):
        self.wordlist = [
            "admin", "login", "uploads", "images", "backup", "config",
            "db", "private", "test", "staging", "api", "dev", "temp",
            "old", "public", "assets", "include", "core", "src", "cas"
        ]

    def run_test(self, domain):
        base_url = f"http://{domain}"
        findings = {}

        try:
            for word in self.wordlist:
                url = f"{base_url}/{word}"

                response = fetch_url(url)
                print(f"Testing URL: {url}")

                if response and response.status_code in [200, 301, 403]:
                    findings[url] = f"Status {response.status_code}"

        except Exception as e:
            return {
                "module": "Directory Bruteforcing",
                "error": str(e)
            }

        # Return a meaningful message even if no directories found
        if not findings:
            findings["Info"] = "No interesting directories discovered"

        return {
            "module": "Directory Bruteforcing",
            "findings": findings
        }
