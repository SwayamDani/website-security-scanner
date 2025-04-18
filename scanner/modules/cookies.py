# scanner/modules/cookies.py

from scanner.utils.http import fetch_cookies

class CookieSecurityModule:
    def run_test(self, domain):
        findings = {}

        cookies = fetch_cookies(domain)

        if cookies is None:
            return {
                "module": "Cookie Security",
                "error": "Failed to fetch cookies"
            }

        if not cookies:
            findings["Cookie Presence"] = "No cookies set"
            return {
                "module": "Cookie Security",
                "findings": findings
            }

        for cookie in cookies:
            cookie_info = {}

            cookie_info["Secure"] = cookie.secure
            cookie_info["HttpOnly"] = "HttpOnly" in cookie._rest.keys()
            cookie_info["SameSite"] = cookie._rest.get("samesite", "None")

            findings[cookie.name] = cookie_info

        return {
            "module": "Cookie Security",
            "findings": findings
        }
