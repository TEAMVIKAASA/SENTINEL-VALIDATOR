import time
import json
from datetime import datetime
from tabulate import tabulate
import scenarios
import verifier
import config

LOG_FILE_PATH = "alerts.log" 

TEST_SUITE = [
    {
        "id": "TC-01",
        "name": "TCP Xmas Scan Attack",
        "func": scenarios.trigger_xmas_scan,
        "signature": "XMAS",
    },
    {
        "id": "TC-02",
        "name": "Oversized ICMP Ping Request",
        "func": scenarios.trigger_oversized_icmp,
        "signature": "ICMP",
    },
    {
        "id": "TC-03",
        "name": "TCP SYN Burst Simulation",
        "func": scenarios.trigger_syn_burst,
        "signature": "SYN",
    }
]

def run_suite():
    print("\n" + "=" * 55)
    print("      PROJECT SENTINEL - ADVERSARIAL VALIDATION SUITE      ")
    print("=" * 55 + "\n")
    
    results = []
    report_data = {
        "timestamp": datetime.now().isoformat(),
        "total_tests": len(TEST_SUITE),
        "passed": 0,
        "failed": 0,
        "details": []
    }

    for test in TEST_SUITE:
        print(f"[*] Running: {test['name']}...")
        start_time = time.time()
        
        start_offset = verifier.get_log_checkpoint(LOG_FILE_PATH)
        
        try:
            test["func"]()
        except Exception as e:
            results.append([test["id"], test["name"], "ERROR", f"Dispatch failed: {e}"])
            report_data["failed"] += 1
            continue

        passed, detail = verifier.verify_file_alert(LOG_FILE_PATH, test["signature"], start_offset)
        duration = round((time.time() - start_time), 2)
        
        status = "PASS" if passed else "FAIL"
        if passed:
            report_data["passed"] += 1
        else:
            report_data["failed"] += 1

        results.append([test["id"], test["name"], status, f"{duration}s | {detail}"])
        report_data["details"].append({
            "id": test["id"],
            "name": test["name"],
            "status": status,
            "latency_seconds": duration,
            "telemetry": detail
        })

    # Summary table print karo
    print("\n" + tabulate(results, headers=["ID", "Test Case", "Verdict", "Telemetry / Latency"], tablefmt="fancy_grid"))

    # Report file save karo
    with open("validation_report.json", "w", encoding="utf-8") as f:
        json.dump(report_data, f, indent=4)
    print("\n[+] Validation report saved to validation_report.json")

if __name__ == "__main__":
    run_suite()