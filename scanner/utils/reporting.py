# scanner/utils/reporting.py

import json
import os
from colorama import Fore, Style, init

# Initialize colorama for colored CLI output
init(autoreset=True)

def generate_report(domain, results):
    """
    Print results with colors, emojis, save report with findings, summary, and security score.
    """
    print("\n--- Security Scan Report ---")
    print(f"Target: {domain}")
    print("----------------------------\n")

    # Initialize counters
    total_modules = len(results)
    passed = 0
    warnings = 0
    errors = 0
    critical_findings = 0

    for result in results:
        module_name = result.get('module')
        print(f"{Style.BRIGHT}{Fore.CYAN}🔎 Module: {module_name}{Style.RESET_ALL}")

        findings = result.get('findings')
        if findings:
            module_error = False
            module_warning = False

            for key, value in findings.items():
                if isinstance(value, dict):
                    print(f"  {Fore.YELLOW}⚠️ {key}:{Style.RESET_ALL}")
                    for subkey, subvalue in value.items():
                        color = Fore.GREEN if subvalue in [True, 'Strict', 'SAMEORIGIN', 'Lax'] else Fore.RED
                        emoji = "✅" if color == Fore.GREEN else "⚠️"
                        print(f"    {emoji} {color}{subkey}: {subvalue}{Style.RESET_ALL}")

                        if color == Fore.RED:
                            module_warning = True

                else:
                    value_str = str(value).lower()

                    if any(kw in value_str for kw in ["vulnerability", "potential", "detected", "error"]) and not value_str.startswith("no obvious"):
                        print(f"  ❌ {Fore.RED}{key}: {value}{Style.RESET_ALL}")
                        module_error = True
                        critical_findings += 1
                    elif value_str == "missing":
                        print(f"  ⚠️ {Fore.YELLOW}{key}: {value}{Style.RESET_ALL}")
                        module_warning = True
                    else:
                        print(f"  ✅ {Fore.GREEN}{key}: {value}{Style.RESET_ALL}")

            if module_error:
                errors += 1
            elif module_warning:
                warnings += 1
            else:
                passed += 1

        else:
            # No findings, but some hard error (like timeout)
            error = result.get('error', 'Unknown Error')
            print(f"  ❌ {Fore.RED}Error: {error}{Style.RESET_ALL}")
            errors += 1

        print()

    # --- Scan Summary ---
    print(f"{Fore.CYAN}📄 Report saved to scanner/reports/{domain.replace('.', '_')}_report.json{Style.RESET_ALL}")

    print("\n--- Scan Summary ---")
    print(f"{Fore.GREEN}✅ Passed: {passed}{Style.RESET_ALL}")
    print(f"{Fore.YELLOW}⚠️ Warnings: {warnings}{Style.RESET_ALL}")
    print(f"{Fore.RED}❌ Errors: {errors}{Style.RESET_ALL}")
    print(f"{Fore.RED}❗ Critical Vulnerabilities: {critical_findings}{Style.RESET_ALL}")

    # --- Security Score Calculation ---
    security_score = 100
    security_score -= warnings * 5           # minor penalty per warning
    security_score -= errors * 10             # bigger penalty per error
    security_score -= critical_findings * 10  # heavy penalty per critical vuln
    security_score = max(0, security_score)   # prevent score below 0

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
    print(f"{Fore.CYAN}🎯 Score: {security_score}/100{Style.RESET_ALL}")
    print(f"{Fore.CYAN}🏅 Grade: {grade}{Style.RESET_ALL}")

    # --- Final JSON Report Content ---
    final_report = {
        "target": domain,
        "modules": results,
        "summary": {
            "total_modules": total_modules,
            "passed": passed,
            "warnings": warnings,
            "errors": errors,
            "critical_vulnerabilities": critical_findings,
            "security_score": security_score,
            "grade": grade
        }
    }

    # Save final JSON report
    os.makedirs("scanner/reports", exist_ok=True)
    report_path = f"scanner/reports/{domain.replace('.', '_')}_report.json"
    with open(report_path, "w") as f:
        json.dump(final_report, f, indent=4)

    print(f"{Fore.CYAN}📄 Report saved to {report_path}{Style.RESET_ALL}")
