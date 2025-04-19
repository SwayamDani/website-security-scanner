# scanner/utils/reporting.py

import json
import os
from colorama import Fore, Style, init

# Initialize colorama for colored CLI output
init(autoreset=True)

def generate_report(domain, results):
    """
    Print results with colors, save report with findings, summary, and security score.
    """
    print("\n--- Security Scan Report ---")
    print(f"Target: {domain}")
    print("----------------------------\n")

    # Initialize counters
    total_modules = len(results)
    passed = 0
    warnings = 0
    errors = 0
    critical_vulns = 0  # <- track number of critical vulnerabilities

    for result in results:
        module_name = result.get('module')
        print(f"{Style.BRIGHT}{Fore.CYAN}Module: {module_name}{Style.RESET_ALL}")

        findings = result.get('findings')
        if findings:
            module_error = False
            module_warning = False

            for key, value in findings.items():
                value_lower = str(value).lower()

                if isinstance(value, dict):
                    print(f"  {Fore.YELLOW}{key}:{Style.RESET_ALL}")
                    for subkey, subvalue in value.items():
                        color = Fore.GREEN if subvalue in [True, 'Strict', 'SAMEORIGIN', 'Lax'] else Fore.RED
                        print(f"    {color}{subkey}: {subvalue}{Style.RESET_ALL}")

                        if color == Fore.RED:
                            module_warning = True
                else:
                    # 🔥 Detect real vulnerabilities
                    if any(keyword in value_lower for keyword in ["sql injection", "xss", "cross-site scripting", "idor", "critical", "vulnerability detected"]):
                        print(f"  {Fore.RED}{key}: {value}{Style.RESET_ALL}")
                        module_error = True
                        critical_vulns += 1  # critical vulns add up individually
                    elif "missing" in value_lower or "warning" in value_lower:
                        print(f"  {Fore.YELLOW}{key}: {value}{Style.RESET_ALL}")
                        module_warning = True
                    else:
                        print(f"  {Fore.GREEN}{key}: {value}{Style.RESET_ALL}")

            if module_error:
                errors += 1
            elif module_warning:
                warnings += 1
            else:
                passed += 1

        else:
            error = result.get('error', 'Unknown Error')
            print(f"  {Fore.RED}Error: {error}{Style.RESET_ALL}")
            errors += 1

        print()

    # --- Scan Summary ---
    print(f"{Fore.CYAN}Report saved to scanner/reports/{domain.replace('.', '_')}_report.json{Style.RESET_ALL}")

    print("\n--- Scan Summary ---")
    print(f"{Fore.CYAN}Total Modules: {total_modules}{Style.RESET_ALL}")
    print(f"{Fore.GREEN}Passed: {passed}{Style.RESET_ALL}")
    print(f"{Fore.YELLOW}Warnings: {warnings}{Style.RESET_ALL}")
    print(f"{Fore.RED}Errors: {errors}{Style.RESET_ALL}")
    print(f"{Fore.RED}Critical Vulnerabilities: {critical_vulns}{Style.RESET_ALL}")

    # --- Security Score Calculation ---
    security_score = 100
    security_score += passed * 5
    security_score -= warnings * 10
    security_score -= errors * 20
    security_score -= critical_vulns * 30  # 🔥 very important: penalty PER CRITICAL
    security_score = max(0, min(security_score, 100))  # Bound between 0 and 100

    if security_score >= 90:
        grade = "A"
    elif security_score >= 80:
        grade = "B"
    elif security_score >= 70:
        grade = "C"
    elif security_score >= 60:
        grade = "D"
    else:
        grade = "F"

    print(f"\n{Style.BRIGHT}--- Final Security Score ---{Style.RESET_ALL}")
    print(f"{Fore.CYAN}Score: {security_score}/100{Style.RESET_ALL}")
    print(f"{Fore.CYAN}Grade: {grade}{Style.RESET_ALL}")

    # --- Final JSON Report Content ---
    final_report = {
        "target": domain,
        "modules": results,
        "summary": {
            "total_modules": total_modules,
            "passed": passed,
            "warnings": warnings,
            "errors": errors,
            "critical_vulnerabilities": critical_vulns,
            "security_score": security_score,
            "grade": grade
        }
    }

    # Save final JSON report
    os.makedirs("scanner/reports", exist_ok=True)
    report_path = f"scanner/reports/{domain.replace('.', '_')}_report.json"
    with open(report_path, "w") as f:
        json.dump(final_report, f, indent=4)

    print(f"{Fore.CYAN}Report saved to {report_path}{Style.RESET_ALL}")
