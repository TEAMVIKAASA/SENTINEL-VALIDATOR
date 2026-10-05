import time
import json
import uuid
from tabulate import tabulate
import scenarios
import verifier

TEST_SUITE = [
    {
        "id": "TC-01",
        "name": "TCP Xmas Scan Attack",
        "func": scenarios.trigger_xmas_scan,
        "signature": "XMAS",
        "timeout": 8.0
    },
    {
        "id": "TC-02",
        "name": "Oversized ICMP Ping Request",
        "func": scenarios.trigger_oversized_icmp,
        "signature": "ICMP",
        "timeout": 8.0
    },
    {
        "id": "TC-03",
        "name": "TCP SYN Burst Simulation",
        "func": scenarios.trigger_syn_burst,
        "signature": "SYN",
        "timeout": 8.0
    }
]

def run_test_suite():
    session_id = f"sentinel_{uuid.uuid4().hex[:8]}"
    print("\n" + "=" * 70)
    print(f"   PROJECT SENTINEL - ADVERSARIAL VALIDATION SUITE [{session_id}]")
    print("=" * 70 + "\n")
    
    table_rows = []
    json_results = []
    
    for test in TEST_SUITE:
        print(f"[*] Executing Test Vector: {test['name']}...")
        start_time = time.time()
        
        # 1. Dispatch crafted adversarial packet(s)
        test["func"]()
        
        # 2. Poll Supabase for detection ingestion
        passed, details = verifier.wait_for_alert(
            expected_signature=test["signature"],
            start_epoch=start_time,
            timeout=test["timeout"]
        )
        
        latency = round(time.time() - start_time, 2)
        verdict = "PASS" if passed else "FAIL"
        
        table_rows.append([test["id"], test["name"], verdict, f"{latency}s | {details}"])
        json_results.append({
            "test_id": test["id"],
            "name": test["name"],
            "verdict": verdict,
            "latency_seconds": latency,
            "telemetry_details": details
        })
        print(f"    --> Verdict: {verdict} ({latency}s)\n")
        time.sleep(1.0)
        
    print(tabulate(table_rows, headers=["ID", "Test Case", "Verdict", "Telemetry / Latency"], tablefmt="fancy_grid"))
    
    # Save validation artifact
    with open("validation_report.json", "w") as f:
        json.dump({
            "session_id": session_id,
            "timestamp": time.time(),
            "results": json_results
        }, f, indent=4)
        
    print("\n[+] Validation report successfully generated -> validation_report.json\n")

if __name__ == "__main__":
    run_test_suite()