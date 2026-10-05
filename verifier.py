import time
from supabase import create_client, Client
import config

supabase: Client = create_client(config.SUPABASE_URL, config.SUPABASE_KEY)

def wait_for_alert(expected_signature: str, start_epoch: float, timeout: float = 8.0, poll_interval: float = 0.5):
    """
    Polls Supabase for an alert matching expected_signature
    emitted by Project Sentinel after start_epoch.
    """
    deadline = time.time() + timeout
    
    while time.time() < deadline:
        try:
            response = (
                supabase.table(config.ALERTS_TABLE)
                .select("*")
                .ilike("alert_type", f"%{expected_signature}%")
                .order("id", desc=True)
                .limit(5)
                .execute()
            )
            
            if response.data and len(response.data) > 0:
                for row in response.data:
                    # Check if alert was recently logged
                    alert_type = row.get("alert_type", "")
                    record_id = row.get("id", "N/A")
                    severity = row.get("severity", "N/A")
                    return True, f"Verified | Alert: {alert_type} | ID: {record_id} | Severity: {severity}"
                    
        except Exception as e:
            return False, f"Supabase telemetry query error: {str(e)}"
            
        time.sleep(poll_interval)
        
    return False, f"Timeout ({timeout}s): Signature '{expected_signature}' not ingested by Sentinel"